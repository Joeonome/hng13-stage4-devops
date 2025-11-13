#!/bin/bash
set -e

# ============================================
# Setup Logging
# ============================================
LOG_DIR="./logs/teardown"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/teardown_${TIMESTAMP}.txt"

# Redirect all output (stdout + stderr) to log file and console
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=============================================="
echo "📜 Logging started: $LOG_FILE"
echo "Timestamp: $(date)"
echo "=============================================="

# ============================================
# Teardown
# ============================================
echo "=== 🧹 Teardown VPCs ==="
sudo vpcctl TEARDOWN_VPCS --VPC_NAME vpcA vpcB

# ============================================
# Verification After Teardown
# ============================================
echo "=== 🔹 Post-Teardown Check ==="
ip netns list
brctl show
ip link show type bridge
ip link show
sudo iptables -t nat -L -n -v

echo "=============================================="
echo "🧾 Teardown complete. Logs saved to: $LOG_FILE"
echo "=============================================="
