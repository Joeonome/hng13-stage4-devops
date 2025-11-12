#!/bin/bash
set -euo pipefail

#========================================
# Helper functions
#========================================
info()    { echo -e "=== $1 ==="; }
run()     { echo "⚡ $ $*"; "$@"; }
ping_test(){ sudo ip netns exec "$1" ping -c 2 "$2" || echo "⚠  Ping $2 from $1 failed"; }
curl_test(){
    local ns=$1 ip=$2 name=$3
    if curl -s -m 3 "http://$ip:8080" | grep -q "$name"; then
        echo "✅ $ns can reach $name server ($ip)"
    else
        echo "❌ $ns cannot reach $name server ($ip)"
    fi
}

#========================================
# VPC Definitions
#========================================
VPCS=(
    "vpcA 10.0.0.0/16 10.0.1.0/24 10.0.2.0/24 eth0 10.0.1.2/24 10.0.2.2/24 ./private-policy.json"
    "vpcB 192.168.0.0/16 192.168.1.0/24 192.168.2.0/24 eth0 192.168.1.2/24 192.168.2.2/24 ./private-policy.json"
)

#========================================
# Create VPCs
#========================================
for v in "${VPCS[@]}"; do
    read -r NAME CIDR PUB_PRI SUB_PRIV INTF PUB_IP PRI_IP POLICY <<<"$v"
    info "🏗 Creating $NAME"
    sudo vpcctl create \
        --VPC_NAME "$NAME" \
        --CIDR_BLOCK "$CIDR" \
        --PUBLIC_SUBNET "$PUB_PRI" \
        --PRIVATE_SUBNET "$SUB_PRIV" \
        --INTERNET_INTERFACE "$INTF" \
        --PUBLIC_HOST_IP "$PUB_IP" \
        --PRIVATE_HOST_IP "$PRI_IP" \
        --FIREWALL_POLICY "$POLICY"
done

#========================================
# Verify and Test VPCs
#========================================
for v in "${VPCS[@]}"; do
    read -r NAME CIDR PUB_PRI SUB_PRIV INTF PUB_IP PRI_IP POLICY <<<"$v"
    info "✅ Verifying $NAME setup"
    
    sudo ip netns list
    sudo ip link show type bridge
    sudo bridge link show

    for ns in "public" "private"; do
        sudo ip netns exec "${NAME}-${ns}" ip addr show "veth${NAME: -1}-${ns:0:3}"
        sudo ip netns exec "${NAME}-${ns}" route -n
    done

    info "🧪 Connectivity Tests for $NAME"
    ping_test "${NAME}-public" "$PUB_IP"
    ping_test "${NAME}-public" "$PRI_IP"
    ping_test "${NAME}-public" "8.8.8.8"

    ping_test "${NAME}-private" "$PRI_IP"
    ping_test "${NAME}-private" "$PUB_IP"
    ping_test "${NAME}-private" "8.8.8.8"
done

#========================================
# Deploy workload servers
#========================================
info "🌐 Deploying workload servers"
for v in "${VPCS[@]}"; do
    read -r NAME CIDR PUB_PRI SUB_PRIV INTF PUB_IP PRI_IP POLICY <<<"$v"
    sudo vpcctl deploy-server --VPC_NAME "$NAME" --PUBLIC_IP "$PUB_IP" --PRIVATE_IP "$PRI_IP"
done

#========================================
# Test host & cross-namespace connectivity
#========================================
for v in "${VPCS[@]}"; do
    read -r NAME CIDR PUB_PRI SUB_PRIV INTF PUB_IP PRI_IP POLICY <<<"$v"

    info "🌐 Testing Host Connectivity for $NAME"
    curl_test "Host" "$PUB_IP" "Public Subnet"
    if ! curl -s -m 3 "http://$PRI_IP:8080" >/dev/null; then
        echo "✅ Host cannot reach Private server (expected)"
    else
        echo "❌ Host can reach Private server (unexpected)"
    fi

    info "🧭 Cross-Namespace Connectivity for $NAME"
    curl_test "${NAME}-public" "$PRI_IP" "Private Subnet"
    curl_test "${NAME}-private" "$PUB_IP" "Public Subnet"
done

#========================================
# VPC Peering
#========================================
info "🔗 Peering VPC A and VPC B"
sudo vpcctl peer \
    --VPC_A vpcA \
    --VPC_B vpcB \
    --PUBLIC_SUBNET_A 10.0.1.0/24 \
    --PUBLIC_SUBNET_B 192.168.1.0/24

# Test peering connectivity
ping_test "vpcA-public" "192.168.1.2"
ping_test "vpcB-public" "10.0.1.2"

#========================================
# Firewall rules
#========================================
info "🚫 Blocking ICMP for VPC B"
sudo vpcctl block-icmp --VPC_NAME vpcB --POLICY_FILE /home/joe/public_no_icmp.json
ping_test "vpcB-public" "8.8.8.8"

#========================================
# Teardown
#========================================
info "🧹 Teardown VPCs"
sudo vpcctl TEARDOWN_VPCS --VPC_NAME vpcA vpcB

info "🔹 Post-Teardown Verification"
ip netns list
brctl show
ip link show type bridge
ip link show
sudo iptables -t nat -L -n -v
