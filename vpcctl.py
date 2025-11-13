#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import json

def RUN(CMD, CHECK=True):
    """Run shell command safely"""
    print(f"⚡ Running: {CMD}")
    RESULT = subprocess.run(CMD, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if CHECK and RESULT.returncode != 0:
        print(f"❌ Command failed: {RESULT.stderr.strip()}")
        sys.exit(1)
    return RESULT.stdout.strip()

def INSTALL_TOOLS():
    print("=== ⚙ Installing required networking tools ===")
    RUN("sudo apt-get update -y && sudo apt-get install -y iproute2 iptables net-tools bridge-utils curl python3 jq")

def CREATE_BRIDGE(VPC_NAME, PUBLIC_SUBNET, PRIVATE_SUBNET):
    BRIDGE = f"br-{VPC_NAME}"
    print(f"=== 🏗 Creating VPC bridge {BRIDGE} ===")
    RUN(f"sudo ip link add {BRIDGE} type bridge || true")
    RUN(f"sudo ip link set {BRIDGE} up")
    PUB_GW = PUBLIC_SUBNET.split('/')[0].rsplit('.', 1)[0] + ".1"
    PRI_GW = PRIVATE_SUBNET.split('/')[0].rsplit('.', 1)[0] + ".1"
    RUN(f"sudo ip addr add {PUB_GW}/{PUBLIC_SUBNET.split('/')[1]} dev {BRIDGE} 2>/dev/null || true")
    RUN(f"sudo ip addr add {PRI_GW}/{PRIVATE_SUBNET.split('/')[1]} dev {BRIDGE} 2>/dev/null || true")
    RUN("sudo brctl show")
    RUN(f"sudo ip addr show {BRIDGE}")
    return BRIDGE

def CREATE_NAMESPACE(VPC_NAME, SUBNET_TYPE, SUBNET_CIDR, BRIDGE, HOST_IP):
    NS = f"{VPC_NAME}-{SUBNET_TYPE}"
    VETH_NS = f"veth{VPC_NAME[-1]}-{SUBNET_TYPE[:3]}"
    VETH_BR = f"{VETH_NS}-br"
    print(f"=== 🌐 Creating {SUBNET_TYPE} subnet ({NS}) ===")
    RUN(f"sudo ip netns add {NS} || true")
    RUN(f"sudo ip link add {VETH_NS} type veth peer name {VETH_BR} || true")
    RUN(f"sudo ip link set {VETH_NS} netns {NS}")
    RUN(f"sudo ip netns exec {NS} ip addr add {HOST_IP} dev {VETH_NS}")
    RUN(f"sudo ip netns exec {NS} ip link set {VETH_NS} up")
    RUN(f"sudo ip netns exec {NS} ip link set lo up")
    if SUBNET_TYPE == "public":
        GW = SUBNET_CIDR.split('/')[0].rsplit('.', 1)[0] + ".1"
        RUN(f"sudo ip netns exec {NS} ip route add default via {GW} || true")
    RUN(f"sudo ip link set {VETH_BR} master {BRIDGE}")
    RUN(f"sudo ip link set {VETH_BR} up")
    return NS

def SETUP_ROUTING(PUBLIC_NS, PRIVATE_NS, PUBLIC_SUBNET, PRIVATE_SUBNET):
    print("=== 🧭 Configuring Inter-Subnet Routes ===")
    PUB_GW = PUBLIC_SUBNET.split('/')[0].rsplit('.', 1)[0] + ".1"
    PRIV_GW = PRIVATE_SUBNET.split('/')[0].rsplit('.', 1)[0] + ".1"
    RUN(f"sudo ip netns exec {PUBLIC_NS} ip route add {PRIVATE_SUBNET} via {PUB_GW} || true")
    RUN(f"sudo ip netns exec {PRIVATE_NS} ip route add {PUBLIC_SUBNET} via {PRIV_GW} || true")

def ENABLE_IP_FORWARDING():
    print("=== 🔥 Enabling IP Forwarding ===")
    RUN("sudo sysctl -w net.ipv4.ip_forward=1")
    if "net.ipv4.ip_forward=1" not in open("/etc/sysctl.conf").read():
        RUN("echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf")


def SETUP_NAT(PUBLIC_SUBNET, INTERNET_INTERFACE):
    """
    Sets up NAT (MASQUERADE) for a public subnet while skipping all
    other private IP ranges (RFC1918) except the current VPC's subnet.
    
    PUBLIC_SUBNET: str, e.g., "10.0.1.0/24"
    INTERNET_INTERFACE: str, e.g., "eth0"
    """
    print(f"=== 🌍 Setting up NAT for Public Subnet {PUBLIC_SUBNET} ===")



    # MASQUERADE all other traffic
    RUN(f"sudo iptables -t nat -C POSTROUTING -s {PUBLIC_SUBNET} -o {INTERNET_INTERFACE} -j MASQUERADE 2>/dev/null || "
        f"sudo iptables -t nat -A POSTROUTING -s {PUBLIC_SUBNET} -o {INTERNET_INTERFACE} -j MASQUERADE")
    APPLY_GLOBAL_ISOLATION() 

def APPLY_VPC_ISOLATION(VPC_A_NAME, VPC_A_PUBLIC_SUBNET, VPC_B_NAME, VPC_B_PUBLIC_SUBNET):
    """
    Enforce isolation between two VPCs before peering.
    Adds OUTPUT chain DROP rules to prevent cross-VPC communication.
    """
    print(f"=== 🔒 Enforcing isolation between {VPC_A_NAME} and {VPC_B_NAME} ===")

    # Namespaces
    VPC_A_NS = f"{VPC_A_NAME}-public"
    VPC_B_NS = f"{VPC_B_NAME}-public"

    # Drop outbound traffic from A→B
    RUN(f"sudo ip netns exec {VPC_A_NS} iptables -C OUTPUT -d {VPC_B_PUBLIC_SUBNET} -j DROP 2>/dev/null || "
        f"sudo ip netns exec {VPC_A_NS} iptables -A OUTPUT -d {VPC_B_PUBLIC_SUBNET} -j DROP")

    # Drop outbound traffic from B→A
    RUN(f"sudo ip netns exec {VPC_B_NS} iptables -C OUTPUT -d {VPC_A_PUBLIC_SUBNET} -j DROP 2>/dev/null || "
        f"sudo ip netns exec {VPC_B_NS} iptables -A OUTPUT -d {VPC_A_PUBLIC_SUBNET} -j DROP")

    print(f"✅ Isolation rules applied between {VPC_A_NAME} ↔ {VPC_B_NAME}")

def APPLY_GLOBAL_ISOLATION():
    """
    Prevents routing between all private CIDR ranges (10.0.0.0/8 <-> 192.168.0.0/16).
    This ensures that separate VPCs cannot communicate through the host by default.
    """
    print("=== 🔒 Applying global VPC isolation rules ===")

    RULES = [
        "sudo iptables -C FORWARD -s 10.0.0.0/8 -d 192.168.0.0/16 -j DROP 2>/dev/null || "
        "sudo iptables -A FORWARD -s 10.0.0.0/8 -d 192.168.0.0/16 -j DROP",

        "sudo iptables -C FORWARD -s 192.168.0.0/16 -d 10.0.0.0/8 -j DROP 2>/dev/null || "
        "sudo iptables -A FORWARD -s 192.168.0.0/16 -d 10.0.0.0/8 -j DROP"
    ]

    for rule in RULES:
        RUN(rule)

    print("✅ Inter-VPC communication blocked until explicit peering is configured.")


def APPLY_FIREWALL(POLICY_FILE, NS, PUBLIC_SUBNET=None, PRIVATE_SUBNET=None):
    print(f"=== 🚧 Applying firewall policy to namespace {NS} from {POLICY_FILE} ===")
    with open(POLICY_FILE) as f:
        POLICY = json.load(f)

    # Replace placeholders if provided
    def replace_cidr(value):
        if not value: 
            return value
        value = value.replace("{PUBLIC_SUBNET}", PUBLIC_SUBNET) if PUBLIC_SUBNET else value
        value = value.replace("{PRIVATE_SUBNET}", PRIVATE_SUBNET) if PRIVATE_SUBNET else value
        return value

    RUN(f"sudo ip netns exec {NS} iptables -F")
    RUN(f"sudo ip netns exec {NS} iptables -X")
    RUN(f"sudo ip netns exec {NS} iptables -P INPUT {POLICY['default_policy']['INPUT']}")
    RUN(f"sudo ip netns exec {NS} iptables -P OUTPUT {POLICY['default_policy']['OUTPUT']}")
    RUN(f"sudo ip netns exec {NS} iptables -P FORWARD {POLICY['default_policy']['FORWARD']}")


    if POLICY.get("loopback", {}).get("allow_input"):
        RUN(f"sudo ip netns exec {NS} iptables -A INPUT -i lo -j ACCEPT")
    if POLICY.get("loopback", {}).get("allow_output"):
        RUN(f"sudo ip netns exec {NS} iptables -A OUTPUT -o lo -j ACCEPT")

    for RULE in POLICY.get("ingress", []):
        ACTION = "ACCEPT" if RULE["action"] == "allow" else "DROP"
        PROTO = "" if RULE["protocol"] == "all" else f"-p {RULE['protocol']}"
        SRC = f"-s {replace_cidr(RULE.get('source'))}" if RULE.get("source") else ""
        DST = f"-d {replace_cidr(RULE.get('destination'))}" if RULE.get("destination") else ""
        RUN(f"sudo ip netns exec {NS} iptables -A INPUT {PROTO} {SRC} {DST} -j {ACTION}")

    for RULE in POLICY.get("egress", []):
        ACTION = "ACCEPT" if RULE["action"] == "allow" else "DROP"
        PROTO = "" if RULE["protocol"] == "all" else f"-p {RULE['protocol']}"
        SRC = f"-s {replace_cidr(RULE.get('source'))}" if RULE.get("source") else ""
        DST = f"-d {replace_cidr(RULE.get('destination'))}" if RULE.get("destination") else ""
        RUN(f"sudo ip netns exec {NS} iptables -A OUTPUT {PROTO} {SRC} {DST} -j {ACTION}")

    print(f"✅ Policy applied successfully to {NS}")



def DEPLOY_SERVER(VPC_NAME, PUBLIC_IP=None, PRIVATE_IP=None):
    """Deploy lightweight HTTP servers in public and private subnets for demo."""
    print(f"=== 🌐 Deploying HTTP servers for VPC {VPC_NAME} ===")

    # Require both IPs
    if not PUBLIC_IP or not PRIVATE_IP:
        print("❌ ERROR: Both --PUBLIC_IP and --PRIVATE_IP are required.")
        print("Usage: sudo vpcctl deploy-server --VPC_NAME <name> --PUBLIC_IP <ip> --PRIVATE_IP <ip>")
        return

    PUB_NS = f"{VPC_NAME}-public"
    PRI_NS = f"{VPC_NAME}-private"

    # Verify namespaces exist
    for ns in [PUB_NS, PRI_NS]:
        print(f"⚡ Checking for namespace {ns}...")
        output = RUN(f"sudo ip netns list", CHECK=False)
        if ns not in output:
            print(f"❌ Namespace {ns} not found. Create the VPC first: sudo vpcctl create --VPC_NAME {VPC_NAME}")
            return

    # Prepare directories
    PUB_DIR = f"/tmp/{VPC_NAME}-public"
    PRI_DIR = f"/tmp/{VPC_NAME}-private"
    RUN(f"sudo rm -rf {PUB_DIR} {PRI_DIR} || true", CHECK=False)
    RUN(f"sudo mkdir -p {PUB_DIR} {PRI_DIR}")
    RUN(f"sudo chmod 755 {PUB_DIR} {PRI_DIR}")

    # HTML content
    PUB_HTML = f"""<!doctype html>
<html><head><title>Public Subnet</title></head><body>
<h1>Public Subnet Server</h1>
<p>✅ Served from <strong>{PUB_DIR}</strong> at {PUBLIC_IP}</p>
<p>Reachable from host and other namespaces.</p>
</body></html>"""

    PRI_HTML = f"""<!doctype html>
<html><head><title>Private Subnet</title></head><body>
<h1>Private Subnet Server</h1>
<p>🔒 Served from <strong>{PRI_DIR}</strong> at {PRIVATE_IP}</p>
<p>Not reachable from host, but reachable internally.</p>
</body></html>"""

    RUN(f"sudo bash -c 'echo \"{PUB_HTML}\" > {PUB_DIR}/index.html'")
    RUN(f"sudo bash -c 'echo \"{PRI_HTML}\" > {PRI_DIR}/index.html'")

    # Kill any existing servers
    for ns in [PUB_NS, PRI_NS]:
        RUN(f"sudo ip netns exec {ns} fuser -k 8080/tcp || true", CHECK=False)

    # Launch new servers
    RUN(f"sudo ip netns exec {PUB_NS} setsid nohup python3 -m http.server 8080 "
        f"--bind {PUBLIC_IP} --directory {PUB_DIR} >/tmp/{VPC_NAME}-public.log 2>&1 < /dev/null &")
    RUN(f"sudo ip netns exec {PRI_NS} setsid nohup python3 -m http.server 8080 "
        f"--bind {PRIVATE_IP} --directory {PRI_DIR} >/tmp/{VPC_NAME}-private.log 2>&1 < /dev/null &")

    RUN("sleep 3")

    # Verify servers are running
    for ns, ip, role in [(PUB_NS, PUBLIC_IP, "public"), (PRI_NS, PRIVATE_IP, "private")]:
        result = RUN(f"sudo ip netns exec {ns} curl -s --max-time 2 http://{ip}:8080", CHECK=False)
        if "HTTP" in result or "html" in result:
            print(f"✅ {role.capitalize()} server responding at {ip}:8080")
        else:
            print(f"⚠  {role.capitalize()} server did not respond at {ip}:8080")

    print(f"🎯 Deployment complete for VPC {VPC_NAME} (Public: {PUBLIC_IP}, Private: {PRIVATE_IP})")




def APPLY_PUBLIC_ICMP_BLOCK(NS, POLICY_FILE="/home/joe/public_no_icmp.json"):
    POLICY_FILE = os.path.expanduser(POLICY_FILE)  # Expand ~ to home directory
    print(f"=== 🚫 Applying ICMP block policy to {NS} using {POLICY_FILE} ===")

    with open(POLICY_FILE) as f:
        POLICY = json.load(f)

    for RULE in POLICY.get("egress", []):
        ACTION = "ACCEPT" if RULE["action"]=="allow" else "DROP"
        PROTO = "" if RULE["protocol"]=="all" else f"-p {RULE['protocol']}"
        DST = f"-d {RULE.get('destination')}" if RULE.get("destination") else ""
        # Check if rule exists
        check_cmd = f"sudo ip netns exec {NS} iptables -C OUTPUT {PROTO} {DST} -j {ACTION}"
        result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            # Rule does not exist, add it
            RUN(f"sudo ip netns exec {NS} iptables -A OUTPUT {PROTO} {DST} -j {ACTION}")

    print(f"✅ ICMP block policy applied to {NS} (idempotent)")




def DELETE_VPC(VPC_NAME, PUBLIC_SUBNET="10.0.1.0/24", PRIVATE_SUBNET="10.0.2.0/24", INTERNET_INTERFACE="eth0"):
    print(f"=== 🧹 Deleting VPC {VPC_NAME} resources ===")
    NS_LIST = [f"{VPC_NAME}-public", f"{VPC_NAME}-private"]
    for NS in NS_LIST:
        RUN(f"sudo ip netns pids {NS} | xargs -r sudo kill -9", CHECK=False)
        RUN(f"sudo ip netns delete {NS} 2>/dev/null || true", CHECK=False)
    LINKS = [
        f"veth{VPC_NAME[-1]}-pub-br",
        f"veth{VPC_NAME[-1]}-pub",
        f"veth{VPC_NAME[-1]}-pri-br",
        f"veth{VPC_NAME[-1]}-pri",
        f"br-{VPC_NAME}"
    ]
    for LINK in LINKS:
        RUN(f"sudo ip link delete {LINK} 2>/dev/null || true", CHECK=False)
    RUN(f"sudo iptables -t nat -D POSTROUTING -s {PUBLIC_SUBNET} -o {INTERNET_INTERFACE} -j MASQUERADE", CHECK=False)
    print(f"✅ All resources for VPC {VPC_NAME} deleted successfully!")

# Rest of functions (DEPLOY_SERVER, PEER_VPCS, TEARDOWN_VPCS, main) remain the same,
# with the only syntax fixes being removal of Bash-style loops like 'for link in $(...)' 
# replaced by Python loops using subprocess result

def PEER_VPCS(VPC_A, VPC_B, PUBLIC_SUBNET_A, PUBLIC_SUBNET_B):
    print(f"=== 🔗 Peering {VPC_A} <-> {VPC_B} ===")

    LINK_A = f"veth{VPC_A}-{VPC_B}"
    LINK_B = f"veth{VPC_B}-{VPC_A}"
    BRIDGE_A = f"br-{VPC_A}"
    BRIDGE_B = f"br-{VPC_B}"


    print(f"=== 🧹 Removing global VPC isolation rules ===")
    RUN(f"sudo iptables -C FORWARD -s 10.0.0.0/8 -d 192.168.0.0/16 -j DROP 2>/dev/null && sudo iptables -D FORWARD -s 10.0.0.0/8 -d 192.168.0.0/16 -j DROP || echo 'Rule not found: 10.0.0.0/8 → 192.168.0.0/16'")
    RUN(f"sudo iptables -C FORWARD -s 192.168.0.0/16 -d 10.0.0.0/8 -j DROP 2>/dev/null && sudo iptables -D FORWARD -s 192.168.0.0/16 -d 10.0.0.0/8 -j DROP || echo 'Rule not found: 192.168.0.0/16 → 10.0.0.0/8'")

    # 1 Create veth pair if it doesn't exist
    RUN(f"ip link show {LINK_A} || sudo ip link add {LINK_A} type veth peer name {LINK_B}")

    # 2 Attach each end to its bridge
    RUN(f"sudo ip link set {LINK_A} master {BRIDGE_A}")
    RUN(f"sudo ip link set {LINK_B} master {BRIDGE_B}")

    # 3 Bring both interfaces up
    RUN(f"sudo ip link set {LINK_A} up")
    RUN(f"sudo ip link set {LINK_B} up")

    # 4 Routes
    RUN(f"sudo ip -n vpcA-public route add 192.168.1.0/24 via 10.0.1.1")
    RUN(f"sudo ip -n vpcB-public route add 10.10.1.0/24 via 192.168.1.1")


    # 6 Optional verification or success message
    print(f"✅ Peering established between {VPC_A} and {VPC_B}")



def TEARDOWN_VPCS(VPC_NAMES, PUBLIC_SUBNET="10.0.1.0/24", PRIVATE_SUBNET="10.0.2.0/24", INTERNET_INTERFACE="eth0"):
    """
    Fully teardown one or more VPCs, including:
    - Namespaces
    - Bridges
    - Local and peering veth pairs
    - NAT rules
    - Firewall rules (global + namespaces)
    """

    if isinstance(VPC_NAMES, str):
        VPC_NAMES = [VPC_NAMES]

    print("=== 🧹 Starting full teardown of VPCs ===")

    # 1 Flush global iptables
    print("🔹 Flushing global iptables tables...")
    for table in ["filter", "nat", "mangle"]:
        RUN(f"sudo iptables -t {table} -F", CHECK=False)
        RUN(f"sudo iptables -t {table} -X", CHECK=False)
    for chain in ["INPUT", "OUTPUT", "FORWARD"]:
        RUN(f"sudo iptables -P {chain} ACCEPT", CHECK=False)

    # 2 Delete namespace resources
    for VPC_NAME in VPC_NAMES:
        print(f"\n=== 🧹 Cleaning VPC: {VPC_NAME} ===")
        for NS in [f"{VPC_NAME}-public", f"{VPC_NAME}-private"]:
            print(f"  - Deleting namespace {NS}")
            RUN(f"sudo ip netns pids {NS} | xargs -r sudo kill -9", CHECK=False)
            RUN(f"sudo ip netns delete {NS} 2>/dev/null || true", CHECK=False)

        # Per-VPC bridge + veth cleanup
        LINKS = [
            f"veth{VPC_NAME[-1]}-pub",
            f"veth{VPC_NAME[-1]}-pub-br",
            f"veth{VPC_NAME[-1]}-pri",
            f"veth{VPC_NAME[-1]}-pri-br",
            f"br-{VPC_NAME}"
        ]
        for LINK in LINKS:
            RUN(f"sudo ip link delete {LINK} 2>/dev/null || true", CHECK=False)

    # 3 Detect and remove inter-VPC peering veths (e.g., vethvpcA-vpcB)
    print("\n🔹 Cleaning persistent peering veth pairs...")
    try:
        RESULT = RUN("ip -o link show | awk -F': ' '{print $2}'", CHECK=False)
        for LINK in RESULT.splitlines():
            LINK = LINK.strip()
            # Normalize name (remove @pair suffix)
            if '@' in LINK:
                LINK = LINK.split('@')[0]

            # Check all combinations (vethvpcA-vpcB, vethvpcB-vpcA)
            for A in VPC_NAMES:
                for B in VPC_NAMES:
                    if A != B:
                        if LINK == f"veth{A}-{B}" or LINK == f"veth{B}-{A}":
                            print(f"  🧹 Removing peering veth: {LINK}")
                            RUN(f"sudo ip link delete {LINK} 2>/dev/null || true", CHECK=False)
    except Exception as e:
        print(f"⚠ Error scanning persistent veths: {e}")

    # 4 Clean leftover bridges just in case
    print("\n🔹 Removing leftover bridges...")
    try:
        BR_LIST = RUN("brctl show | awk 'NR>1 {print $1}'", CHECK=False)
        for BR in BR_LIST.splitlines():
            BR = BR.strip()
            if BR.startswith("br-"):
                RUN(f"sudo ip link set {BR} down 2>/dev/null || true", CHECK=False)
                RUN(f"sudo brctl delbr {BR} 2>/dev/null || true", CHECK=False)
    except Exception:
        pass

    # 5 Remove NAT MASQUERADE rules for each VPC’s public subnet
    for VPC_NAME in VPC_NAMES:
        RUN(f"sudo iptables -t nat -D POSTROUTING -s {PUBLIC_SUBNET} -o {INTERNET_INTERFACE} -j MASQUERADE", CHECK=False)

    print("\n✅ Full teardown complete for:", ", ".join(VPC_NAMES))



def main():
    PARSER = argparse.ArgumentParser(description="vpcctl - Virtual VPC Management Tool")
    SUBPARSERS = PARSER.add_subparsers(dest="COMMAND", required=True)
    CREATE_PARSER = SUBPARSERS.add_parser("create", help="Create a new VPC")
    CREATE_PARSER.add_argument("--VPC_NAME", required=True)
    CREATE_PARSER.add_argument("--CIDR_BLOCK", required=True)
    CREATE_PARSER.add_argument("--PUBLIC_SUBNET", required=True)
    CREATE_PARSER.add_argument("--PRIVATE_SUBNET", required=True)
    CREATE_PARSER.add_argument("--INTERNET_INTERFACE", required=True)
    CREATE_PARSER.add_argument("--FIREWALL_POLICY", required=False)
    CREATE_PARSER.add_argument("--PUBLIC_HOST_IP", required=False, default="10.0.1.2/24")
    CREATE_PARSER.add_argument("--PRIVATE_HOST_IP", required=False, default="10.0.2.2/24")

    DEPLOY_PARSER = SUBPARSERS.add_parser("deploy-server", help="Deploy demo HTTP servers in a VPC")
    DEPLOY_PARSER.add_argument("--VPC_NAME", required=True)
    DEPLOY_PARSER.add_argument("--PUBLIC_IP", required=True, help="Public subnet IP for HTTP server")
    DEPLOY_PARSER.add_argument("--PRIVATE_IP", required=True, help="Private subnet IP for HTTP server")

    ICMP_PARSER = SUBPARSERS.add_parser("block-icmp", help="Block ICMP from public subnet to internet")
    ICMP_PARSER.add_argument("--VPC_NAME", required=True)
    ICMP_PARSER.add_argument(
        "--POLICY_FILE",
        required=False,
        default="~/public_no_icmp.json",
        help="Path to JSON firewall policy (default: ~/public_no_icmp.json)"
    )


    ISOLATE_PARSER = SUBPARSERS.add_parser("isolate-vpcs", help="Block cross-VPC communication before peering")
    ISOLATE_PARSER.add_argument("--VPC_A", required=True)
    ISOLATE_PARSER.add_argument("--VPC_A_SUBNET", required=True)
    ISOLATE_PARSER.add_argument("--VPC_B", required=True)
    ISOLATE_PARSER.add_argument("--VPC_B_SUBNET", required=True)


    DELETE_PARSER = SUBPARSERS.add_parser("TEARDOWN_VPCS", help="Teardown one or more VPCs completely")
    DELETE_PARSER.add_argument("--VPC_NAME", nargs="+", required=True, help="One or more VPC names to teardown")
    DELETE_PARSER.add_argument("--PUBLIC_SUBNET", required=False, default="10.0.1.0/24")
    DELETE_PARSER.add_argument("--PRIVATE_SUBNET", required=False, default="10.0.2.0/24")
    DELETE_PARSER.add_argument("--INTERNET_INTERFACE", required=False, default="eth0")


    PEER_PARSER = SUBPARSERS.add_parser("peer", help="Peer two VPCs")
    PEER_PARSER.add_argument("--VPC_A", required=True)
    PEER_PARSER.add_argument("--VPC_B", required=True)
    PEER_PARSER.add_argument("--PUBLIC_SUBNET_A", required=True)
    PEER_PARSER.add_argument("--PUBLIC_SUBNET_B", required=True)

    ARGS = PARSER.parse_args()

    if ARGS.COMMAND == "create":
        DELETE_VPC(
            VPC_NAME=ARGS.VPC_NAME,
            PUBLIC_SUBNET=ARGS.PUBLIC_SUBNET,
            PRIVATE_SUBNET=ARGS.PRIVATE_SUBNET,
            INTERNET_INTERFACE=ARGS.INTERNET_INTERFACE
        )
        INSTALL_TOOLS()
        BRIDGE = CREATE_BRIDGE(ARGS.VPC_NAME, ARGS.PUBLIC_SUBNET, ARGS.PRIVATE_SUBNET)
        PUBLIC_NS = CREATE_NAMESPACE(ARGS.VPC_NAME, "public", ARGS.PUBLIC_SUBNET, BRIDGE, ARGS.PUBLIC_HOST_IP)
        PRIVATE_NS = CREATE_NAMESPACE(ARGS.VPC_NAME, "private", ARGS.PRIVATE_SUBNET, BRIDGE, ARGS.PRIVATE_HOST_IP)
        SETUP_ROUTING(PUBLIC_NS, PRIVATE_NS, ARGS.PUBLIC_SUBNET, ARGS.PRIVATE_SUBNET)
        ENABLE_IP_FORWARDING()
        SETUP_NAT(ARGS.PUBLIC_SUBNET, ARGS.INTERNET_INTERFACE)
        if ARGS.FIREWALL_POLICY:
                APPLY_FIREWALL(
            ARGS.FIREWALL_POLICY,
            PRIVATE_NS,
            PUBLIC_SUBNET=ARGS.PUBLIC_SUBNET,
            PRIVATE_SUBNET=ARGS.PRIVATE_SUBNET
        )

        print(f"✅ VPC {ARGS.VPC_NAME} creation complete!")

    elif ARGS.COMMAND == "deploy-server":
                DEPLOY_SERVER(ARGS.VPC_NAME, PUBLIC_IP=ARGS.PUBLIC_IP, PRIVATE_IP=ARGS.PRIVATE_IP)

    elif ARGS.COMMAND == "block-icmp":
        PUBLIC_NS = f"{ARGS.VPC_NAME}-public"
        APPLY_PUBLIC_ICMP_BLOCK(PUBLIC_NS, POLICY_FILE=ARGS.POLICY_FILE)

    elif ARGS.COMMAND == "delete":
        DELETE_VPC(ARGS.VPC_NAME)
        print(f"✅ VPC {ARGS.VPC_NAME} deleted successfully!")

    elif ARGS.COMMAND == "TEARDOWN_VPCS":
        TEARDOWN_VPCS(
            VPC_NAMES=ARGS.VPC_NAME,
            PUBLIC_SUBNET=ARGS.PUBLIC_SUBNET,
            PRIVATE_SUBNET=ARGS.PRIVATE_SUBNET,
            INTERNET_INTERFACE=ARGS.INTERNET_INTERFACE
        )

    elif ARGS.COMMAND == "isolate-vpcs":
        APPLY_VPC_ISOLATION(ARGS.VPC_A, ARGS.VPC_A_SUBNET, ARGS.VPC_B, ARGS.VPC_B_SUBNET)


    elif ARGS.COMMAND == "peer":
        PEER_VPCS(ARGS.VPC_A, ARGS.VPC_B, ARGS.PUBLIC_SUBNET_A, ARGS.PUBLIC_SUBNET_B)

if __name__ == "__main__":
    main()