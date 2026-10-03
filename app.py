#!/usr/bin/env python3
'''
sudo ip tuntap add dev tap0 mode tap
sudo ip addr add 10.20.30.2/24 dev tap0
sudo ip link set dev tap0 up

sudo ip route add 172.16.100.0/24 via 10.20.30.1
sudo ip route add 192.168.100.0/24 via 10.20.30.1
sudo ip route add 192.168.200.0/24 via 10.20.30.1

sudo ufw allow 6653/tcp
http://127.0.0.1:5003
'''

import csv
import os
import re
import socket
import subprocess
import sys
import paramiko
import time
import threading

from collections import deque
from datetime import datetime
from flask import Flask, jsonify, render_template


BASE_DIR = "/home/osboxes/5280/lab5"
CSV_FILE = os.path.join(BASE_DIR, "SSHInfo.csv")

TAP_INTERFACE = "tap0"
CONTROLLER_IP = "10.20.30.2"
CONTROLLER_PREFIX = "24"
FLOODLIGHT_PORT = 6653

REQUIRED_ROUTES = [
    ("172.16.100.0/24", "10.20.30.1", "tap0"),
    ("192.168.100.0/24", "10.20.30.1", "tap0"),
    ("192.168.200.0/24", "10.20.30.1", "tap0"),
]

CISCO_STATIC_ROUTES = {
    "R4": [
        "ip route 192.168.100.0 255.255.255.0 172.16.100.2",
        "ip route 192.168.200.0 255.255.255.0 172.16.100.2",
    ],
    "R2": [
        "ip route 10.20.30.0 255.255.255.0 172.16.100.1",
        "ip route 192.168.100.0 255.255.255.0 192.168.200.1",
    ],
    "R1": [
        "ip route 10.20.30.0 255.255.255.0 192.168.200.2",
    ],
}

app = Flask(__name__)

packet_in_count = 0
packet_lock = threading.Lock()

# Keep the most recent 60 points = 5 minutes
packet_history = deque(maxlen=60)

tshark_process = None

mininet_channel_global = None

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/packet-in")
def packet_in_api():
    return jsonify(list(packet_history))

@app.route("/api/generate-traffic", methods=["POST"])
def generate_traffic():
    global mininet_channel_global

    if mininet_channel_global is None:
        return jsonify({
            "success": False,
            "message": "Mininet channel is not available."
        }), 500

    try:
        run_mininet_command(
            mininet_channel_global,
            "h1 ip neigh flush all"
        )

        run_mininet_command(
            mininet_channel_global,
            "h2 ip neigh flush all"
        )

        run_mininet_command(
            mininet_channel_global,
            "pingall"
        )

        return jsonify({
            "success": True,
            "message": "Test traffic generated successfully."
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": str(exc)
        }), 500

def fail(message):
    print(f"[ERROR] {message}")
    sys.exit(1)


def run_local(command):
    result = subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True
    )

    return result.returncode, result.stdout.strip(), result.stderr.strip()


def load_ssh_info():
    devices = {}

    if not os.path.exists(CSV_FILE):
        fail(f"{CSV_FILE} does not exist.")

    with open(CSV_FILE, "r", newline="") as file:
        reader = csv.reader(file)

        for row_number, row in enumerate(reader, start=1):
            if not row:
                continue

            if len(row) != 4:
                fail(
                    f"Invalid SSHInfo.csv format on line {row_number}. "
                    "Expected 4 columns."
                )

            device, ip, username, password = [
                value.strip() for value in row
            ]

            devices[device] = {
                "ip": ip,
                "username": username,
                "password": password
            }

    required_devices = ["R1", "R2", "R4", "mininetVM"]

    for device in required_devices:
        if device not in devices:
            fail(f"{device} is missing from SSHInfo.csv.")

    return devices


def check_tap0():
    print("[CHECK] Checking tap0...")

    code, output, error = run_local(
        f"ip -br link show {TAP_INTERFACE}"
    )

    if code != 0:
        fail(f"{TAP_INTERFACE} does not exist.")

    if "UP" not in output:
        fail(f"{TAP_INTERFACE} is not UP.")

    code, output, error = run_local(
        f"ip -4 addr show dev {TAP_INTERFACE}"
    )

    expected = f"{CONTROLLER_IP}/{CONTROLLER_PREFIX}"

    if expected not in output:
        fail(
            f"{TAP_INTERFACE} does not have expected address "
            f"{expected}."
        )

    print(
        f"[OK] {TAP_INTERFACE} is UP with "
        f"{CONTROLLER_IP}/{CONTROLLER_PREFIX}"
    )


def check_routes():
    print("[CHECK] Checking Linux static routes...")

    code, route_table, error = run_local("ip route")

    if code != 0:
        fail("Unable to read Linux routing table.")

    missing_routes = []

    for network, gateway, interface in REQUIRED_ROUTES:
        expected_parts = [
            network,
            f"via {gateway}",
            f"dev {interface}"
        ]

        matching_line = None

        for line in route_table.splitlines():
            if line.startswith(network):
                matching_line = line
                break

        if matching_line is None:
            missing_routes.append(network)
            continue

        if not all(part in matching_line for part in expected_parts):
            fail(
                f"Route for {network} exists but is incorrect:\n"
                f"  {matching_line}"
            )

        print(
            f"[OK] {network} via {gateway} dev {interface}"
        )

    if missing_routes:
        fail(
            "Missing required Linux route(s): "
            + ", ".join(missing_routes)
        )


def check_floodlight():
    print("[CHECK] Checking Floodlight TCP port 6653...")

    try:
        with socket.create_connection(
            (CONTROLLER_IP, FLOODLIGHT_PORT),
            timeout=2
        ):
            pass

    except OSError as exc:
        fail(
            f"Floodlight is not reachable on "
            f"{CONTROLLER_IP}:{FLOODLIGHT_PORT}: {exc}"
        )

    print(
        f"[OK] Floodlight is listening on "
        f"{CONTROLLER_IP}:{FLOODLIGHT_PORT}"
    )


def check_tshark():
    print("[CHECK] Checking tshark...")

    code, output, error = run_local("which tshark")

    if code != 0 or not output:
        fail("tshark is not installed.")

    print(f"[OK] tshark found at {output}")

def ssh_router_through_cisco(jump_device, target_device,
                             target_ip, target_name):
    """
    SSH to a Cisco jump router, then use the Cisco IOS
    outbound SSH client to reach the next router.
    """

    print(
        f"[SSH] Connecting to {target_name} "
        f"through Cisco jump router..."
    )

    jump_client = ssh_connect(jump_device)
    channel = jump_client.invoke_shell()

    # Read initial jump-router prompt
    print(read_channel(channel, 1), end="")

    channel.send("terminal length 0\n")
    print(read_channel(channel, 0.5), end="")

    # Cisco IOS outbound SSH
    command = (
        f"ssh -l {target_device['username']} "
        f"{target_ip}\n"
    )

    channel.send(command)

    buffer = ""
    password_sent = False
    start = time.time()

    while time.time() - start < 15:
        if channel.recv_ready():
            data = channel.recv(65535).decode(errors="ignore")
            buffer += data
            print(data, end="")

            lower = buffer.lower()

            # First-time SSH host-key confirmation if IOS asks
            if (
                "continue connecting" in lower
                or "[yes/no]" in lower
            ):
                channel.send("yes\n")
                buffer = ""
                continue

            # Target router password
            if "password:" in lower and not password_sent:
                channel.send(target_device["password"] + "\n")
                password_sent = True
                buffer = ""
                continue

            # Detect target privileged prompt, e.g. R2# or R1#
            if f"{target_name}#" in buffer:
                print(
                    f"\n[OK] Reached {target_name} "
                    "through jump router."
                )
                return jump_client, channel

        time.sleep(0.2)

    jump_client.close()
    fail(
        f"Unable to SSH to {target_name} "
        f"through Cisco jump router."
    )

def configure_cisco_on_channel(device_name, channel):
    print(
        f"\n[ROUTER] Configuring static routes "
        f"on {device_name}..."
    )

    channel.send("terminal length 0\n")
    print(read_channel(channel, 0.5), end="")

    channel.send("configure terminal\n")
    output = read_channel(channel, 0.5)
    print(output, end="")

    if "(config)" not in output:
        fail(
            f"{device_name} did not enter "
            "configuration mode."
        )

    for route in CISCO_STATIC_ROUTES[device_name]:
        print(f"[CONFIG] {device_name}: {route}")

        channel.send(route + "\n")
        output = read_channel(channel, 0.5)
        print(output, end="")

        if "% Invalid" in output:
            fail(
                f"{device_name} rejected route: {route}"
            )

    channel.send("end\n")
    print(read_channel(channel, 0.5), end="")

    channel.send("write memory\n")
    print(read_channel(channel, 2), end="")

    channel.send("show ip route\n")
    route_table = read_channel(channel, 2)

    print(
        f"\n[{device_name}] Current routing table "
        "after write memory:"
    )
    print(route_table)

    print(
        f"[OK] {device_name} configuration completed."
    )

def read_channel(channel, wait=1.0):
    time.sleep(wait)

    output = ""

    while channel.recv_ready():
        output += channel.recv(65535).decode(
            errors="ignore"
        )

        time.sleep(0.1)

    return output

def configure_cisco_routes(device_name, device, client=None):
    print(f"\n[ROUTER] Configuring static routes on {device_name}...")

    own_client = False

    if client is None:
        client = ssh_connect(device)
        own_client = True

    try:
        channel = client.invoke_shell()
        print(read_channel(channel, 1), end="")

        channel.send("terminal length 0\n")
        print(read_channel(channel, 0.5), end="")

        channel.send("configure terminal\n")
        output = read_channel(channel, 0.5)
        print(output, end="")

        if "(config)" not in output:
            fail(f"{device_name} did not enter configuration mode.")

        for route in CISCO_STATIC_ROUTES[device_name]:
            print(f"[CONFIG] {device_name}: {route}")
            channel.send(route + "\n")
            print(read_channel(channel, 0.5), end="")

        channel.send("end\n")
        print(read_channel(channel, 0.5), end="")

        channel.send("write memory\n")
        print(read_channel(channel, 2), end="")

        channel.send("show ip route\n")
        route_table = read_channel(channel, 2)

        print(f"\n[{device_name}] Current routing table:")
        print(route_table)

    finally:
        client.close()

    print(f"[OK] {device_name} configuration completed.")

def configure_all_routers(devices):
    print("\n" + "=" * 60)
    print("Cisco Static Routing")
    print("=" * 60)

    # -----------------------------------------------------
    # D1 - R4 is directly reachable from Controller VM
    # -----------------------------------------------------
    print("\n[STEP 1] Direct SSH to R4")

    configure_cisco_routes(
        "R4",
        devices["R4"]
    )

    # -----------------------------------------------------
    # D2 - R2 does not yet know how to reach 10.20.30.0/24.
    # SSH to R4 first, then use IOS outbound SSH to R2.
    # -----------------------------------------------------
    print("\n[STEP 2] SSH to R2 through R4")

    r4_client, r2_channel = ssh_router_through_cisco(
        devices["R4"],
        devices["R2"],
        "172.16.100.2",
        "R2"
    )

    try:
        configure_cisco_on_channel(
            "R2",
            r2_channel
        )
    finally:
        r4_client.close()

    # R2 now has:
    # 10.20.30.0/24 -> 172.16.100.1
    # Controller can therefore SSH directly to R2.

    # -----------------------------------------------------
    # D3 - SSH directly to R2, then outbound SSH to R1.
    # -----------------------------------------------------
    print("\n[STEP 3] SSH to R1 through R2")

    r2_client, r1_channel = ssh_router_through_cisco(
        devices["R2"],
        devices["R1"],
        "192.168.200.1",
        "R1"
    )

    try:
        configure_cisco_on_channel(
            "R1",
            r1_channel
        )
    finally:
        r2_client.close()

    print("\n[OK] Step D completed successfully.")

def ssh_connect(device):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    print(
        f"[SSH] Connecting to {device['ip']} "
        f"as {device['username']}..."
    )

    try:
        client.connect(
            hostname=device["ip"],
            username=device["username"],
            password=device["password"],
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
    except Exception as exc:
        fail(f"SSH connection failed: {exc}")

    return client


def get_mininet_ip_from_r1(r1):
    client = ssh_connect(r1)

    try:
        stdin, stdout, stderr = client.exec_command(
            "show ip dhcp binding"
        )

        output = stdout.read().decode(
            errors="ignore"
        )

        error = stderr.read().decode(
            errors="ignore"
        )

    finally:
        client.close()

    if error.strip():
        print(f"[WARNING] R1 stderr: {error.strip()}")

    print("[R1] DHCP bindings:")
    print(output)

    matches = re.findall(
        r"\b192\.168\.100\.(?:"
        r"25[0-5]|2[0-4]\d|1?\d?\d"
        r")\b",
        output
    )

    unique_matches = sorted(set(matches))

    if len(unique_matches) == 0:
        fail("No 192.168.100.x DHCP lease found on R1.")

    if len(unique_matches) > 1:
        fail(
            "More than one DHCP lease was found: "
            + ", ".join(unique_matches)
        )

    mininet_ip = unique_matches[0]

    print(
        f"[OK] Mininet VM DHCP address is {mininet_ip}"
    )

    return mininet_ip


def update_mininet_ip(new_ip):
    rows = []
    updated = False

    with open(CSV_FILE, "r", newline="") as file:
        reader = csv.reader(file)

        for row in reader:
            if not row:
                continue

            if len(row) != 4:
                fail(
                    "SSHInfo.csv changed while the program "
                    "was running."
                )

            if row[0].strip() == "mininetVM":
                old_ip = row[1].strip()
                row[1] = new_ip
                updated = True

                if old_ip == new_ip:
                    print(
                        f"[OK] SSHInfo.csv already contains "
                        f"{new_ip} for mininetVM."
                    )
                else:
                    print(
                        f"[UPDATE] mininetVM IP: "
                        f"{old_ip or '<blank>'} -> {new_ip}"
                    )

            rows.append(row)

    if not updated:
        fail("mininetVM entry was not found in SSHInfo.csv.")

    with open(CSV_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerows(rows)

    print("[OK] SSHInfo.csv updated.")

def wait_for_prompt(channel, prompt_text, timeout=15):
    buffer = ""
    start = time.time()

    while time.time() - start < timeout:
        if channel.recv_ready():
            data = channel.recv(65535).decode(errors="ignore")
            buffer += data
            print(data, end="")

            if prompt_text in buffer:
                return buffer

        time.sleep(0.2)

    fail(f"Timed out waiting for prompt: {prompt_text}")


def run_sudo_command(client, command, password, timeout=30):
    stdin, stdout, stderr = client.exec_command(
        f"sudo -S -p '' {command}",
        get_pty=True
    )

    stdin.write(password + "\n")
    stdin.flush()

    output = stdout.read().decode(errors="ignore")
    error = stderr.read().decode(errors="ignore")

    if error.strip():
        print(error, end="")

    if "incorrect password" in output.lower():
        fail(f"sudo authentication failed for command: {command}")

    return output

def wait_for_mininet(channel, password, timeout=30):
    buffer = ""
    password_sent = False
    start = time.time()

    while time.time() - start < timeout:
        if channel.recv_ready():
            data = channel.recv(65535).decode(errors="ignore")
            buffer += data
            print(data, end="")

            # Handle sudo password prompt
            if (
                "password" in buffer.lower()
                and not password_sent
            ):
                channel.send(password + "\n")
                password_sent = True
                buffer = ""

            # Mininet is ready
            if "mininet>" in buffer:
                return buffer

        time.sleep(0.2)

    fail("Timed out waiting for Mininet CLI.")

def start_mininet(device):
    print("\n" + "=" * 60)
    print("Initialize Default Mininet Topology")
    print("=" * 60)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:
        client.connect(
            hostname=device["ip"],
            username=device["username"],
            password=device["password"],
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
    except Exception as exc:
        fail(f"Unable to SSH to Mininet VM: {exc}")

    print("[MININET] Cleaning previous Mininet state...")

    cleanup_output = run_sudo_command(
        client,
        "mn -c",
        device["password"]
    )

    print(cleanup_output)

    print("[MININET] Starting default Mininet topology...")

    channel = client.invoke_shell()

    # Clear initial Ubuntu shell banner/prompt
    time.sleep(1)
    if channel.recv_ready():
        initial = channel.recv(65535).decode(errors="ignore")
        print(initial, end="")

    channel.send("sudo mn\n")

    # Do not call read_channel() here.
    # This function must see the Mininet prompt itself.
    wait_for_mininet(
        channel,
        device["password"],
        timeout=30
    )

    print("\n[OK] Default Mininet topology is running.")

    return client, channel

def run_mininet_command(channel, command, timeout=15):
    print(f"[MININET] {command}")

    channel.send(command + "\n")

    buffer = ""
    start = time.time()

    while time.time() - start < timeout:
        if channel.recv_ready():
            data = channel.recv(65535).decode(errors="ignore")
            buffer += data
            print(data, end="")

            if "mininet>" in buffer:
                return buffer

        time.sleep(0.2)

    fail(
        f"Timed out waiting for Mininet prompt "
        f"after command: {command}"
    )

def configure_ovs(channel):
    print("\n" + "=" * 60)
    print("Configure Open vSwitch")
    print("=" * 60)

    # Force s1 to use OpenFlow 1.3
    #run_mininet_command(
        #channel,
        #"sh ovs-vsctl set bridge s1 protocols=OpenFlow13"
    #)

    # Point s1 to Floodlight
    run_mininet_command(
        channel,
        "sh ovs-vsctl set-controller "
        "s1 tcp:10.20.30.2:6653"
    )

    # Display configured OpenFlow version
    #protocols_output = run_mininet_command(
        #channel,
        #"sh ovs-vsctl get bridge s1 protocols"
    #)

    #if "OpenFlow13" not in protocols_output:
        #fail(
            #"s1 was not successfully configured "
            #"for OpenFlow 1.3."
        #)

    # Display configured controller
    controller_output = run_mininet_command(
        channel,
        "sh ovs-vsctl get-controller s1"
    )

    if "tcp:10.20.30.2:6653" not in controller_output:
        fail(
            "s1 controller configuration is incorrect."
        )

    #print(
        #"\n[OK] s1 is configured for OpenFlow 1.3."
    #)
    
    print(
        "[OK] s1 controller is "
        "tcp:10.20.30.2:6653."
    )

def verify_openflow_connectivity(channel, timeout=20):
    print("\n" + "=" * 60)
    print("Verify OpenFlow Connectivity")
    print("=" * 60)

    print(
        f"[CHECK] Waiting up to {timeout} seconds "
        "for OVS to connect to Floodlight..."
    )

    start = time.time()

    while time.time() - start < timeout:
        output = run_mininet_command(
            channel,
            "sh ovs-vsctl show"
        )

        if "is_connected: true" in output:
            elapsed = time.time() - start

            print(
                f"\n[OK] OVS connected to Floodlight "
                f"after {elapsed:.1f} seconds."
            )
            print(
                "[OK] Controller: tcp:10.20.30.2:6653"
            )
            return

        elapsed = time.time() - start
        remaining = max(0, timeout - elapsed)

        print(
            f"[WAIT] Not connected yet. "
            f"{remaining:.0f} seconds remaining..."
        )

        time.sleep(1)

    fail(
        f"OVS did not establish OpenFlow connectivity "
        f"with Floodlight within {timeout} seconds."
    )

def start_packet_in_capture():
    global tshark_process

    print("\n" + "=" * 60)
    print("Start OpenFlow Packet_In Monitoring")
    print("=" * 60)

    command = [
        "/usr/bin/tshark",
        "-l",
        "-n",
        "-i", "tap0",
        "-f", "tcp port 6653",
        "-Y", "openflow_v6.type == 10",
        "-T", "fields",
        "-e", "openflow_v6.type"
    ]

    try:
        tshark_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
    except Exception as exc:
        fail(f"Unable to start tshark: {exc}")

    time.sleep(2)

    if tshark_process.poll() is not None:
        error = tshark_process.stderr.read()
        fail(f"tshark exited unexpectedly:\n{error}")

    threading.Thread(
        target=packet_capture_worker,
        daemon=True
    ).start()

    threading.Thread(
        target=packet_sample_worker,
        daemon=True
    ).start()

    print("[OK] OpenFlow 1.5 Packet_In capture started on tap0.")

def packet_capture_worker():
    global packet_in_count

    for line in tshark_process.stdout:
        line = line.strip()

        if not line:
            continue

        # Usually one "10" per Packet_In.
        # Count every type 10 reported by tshark.
        values = [
            value.strip()
            for value in line.replace(",", " ").split()
        ]

        count = sum(
            1 for value in values
            if value == "10"
        )

        if count:
            with packet_lock:
                packet_in_count += count

def packet_sample_worker():
    global packet_in_count

    while True:
        time.sleep(5)

        with packet_lock:
            current_count = packet_in_count
            packet_in_count = 0

        packet_history.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "count": current_count
        })

        print(
            f"[PACKET_IN] "
            f"{packet_history[-1]['time']} -> "
            f"{current_count} messages / 5 sec"
        )

def precheck():
    print("=" * 60)
    print("Controller VM Pre-check")
    print("=" * 60)

    check_tap0()
    check_routes()
    check_floodlight()
    check_tshark()

    print("[OK] All Controller VM pre-checks passed.\n")

def main():
    if os.geteuid() != 0:
        fail(
            "Run this program with sudo:\n"
            "sudo python3 app.py"
        )

    # Load R1/R2/R4/mininetVM SSH credentials
    devices = load_ssh_info()

    # ---------------------------------------------------------
    # PRE-CHECK
    # ---------------------------------------------------------
    precheck()

    # ---------------------------------------------------------
    # STEP D
    # Configure routing before anything else
    # Order: R4 -> R2 -> R1
    # Each router: configure routes -> wr -> show ip route
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("Configure Traditional Router Static Routes")
    print("=" * 60)

    configure_all_routers(devices)

    print("\n[OK] Configure Traditional Router Static Routes successfully.")

    # ---------------------------------------------------------
    # STEP A
    # SSH to R1 and discover Mininet VM DHCP address
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("Discover Mininet VM IP Address")
    print("=" * 60)

    mininet_ip = get_mininet_ip_from_r1(
        devices["R1"]
    )

    update_mininet_ip(mininet_ip)

    # Update the copy already loaded in memory
    devices["mininetVM"]["ip"] = mininet_ip

    print(
        f"[OK] Discover Mininet VM IP Address successfully. "
        f"Mininet VM IP: {mininet_ip}"
    )

    # ---------------------------------------------------------
    # STEP B
    # Added next:
    # SSH Mininet VM
    # sudo mn -c
    # sudo mn
    # ---------------------------------------------------------
    global mininet_channel_global

    mininet_client, mininet_channel = start_mininet(
        devices["mininetVM"]
    )

    mininet_channel_global = mininet_channel

    print("[OK] Initialize Default Mininet Topology successfully.")

    # ---------------------------------------------------------
    # STEP C
    # Added after Step B:
    # Configure s1 for OpenFlow13
    # Set controller tcp:10.20.30.2:6653
    # ---------------------------------------------------------
    configure_ovs(mininet_channel)

    print("[OK] Configure Open vSwitch successfully.")

    # ---------------------------------------------------------
    # STEP E
    # Added after Step C:
    # ovs-vsctl show
    # verify is_connected: true
    # ---------------------------------------------------------
    verify_openflow_connectivity(
        mininet_channel
    )

    print("[OK] OpenFlow Connectivity completed successfully.")

    # ---------------------------------------------------------
    # STEP F
    # Added after Step E:
    # tshark Packet_In monitoring
    # Flask + Bootstrap + Chart.js
    # ---------------------------------------------------------
    start_packet_in_capture()

    print("\n" + "=" * 60)
    print("OpenFlow Packet_In Monitor")
    print("=" * 60)
    print("Open Firefox on the Controller VM:")
    print("http://127.0.0.1:5003")
    print("\nPress Ctrl+C to stop the application.")

    app.run(
        host="127.0.0.1",
        port=5003,
        debug=False,
        use_reloader=False
    )


    print("\n" + "=" * 60)
    print("Current automation stages completed.")
    print("=" * 60)

if __name__ == "__main__":
    main()