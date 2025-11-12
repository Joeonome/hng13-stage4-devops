#========================================
		# Teardown
		#========================================
		echo "=== 🧹 Teardown VPCs ==="
		sudo vpcctl TEARDOWN_VPCS --VPC_NAME vpcA vpcB

		#========================================
		# Verification After Teardown
		#========================================
		echo "=== 🔹 Post-Teardown Check ==="
		ip netns list
		brctl show
		ip link show type bridge
		ip link show
		sudo iptables -t nat -L -n -v