		#!/bin/bash
		set -e
		#========================================
		# VPC Creation
		#========================================
		echo "=== 🏗 Creating VPC A ==="
		sudo vpcctl create \
		    --VPC_NAME vpcA \
		    --CIDR_BLOCK 10.0.0.0/16 \
		    --PUBLIC_SUBNET 10.0.1.0/24 \
		    --PRIVATE_SUBNET 10.0.2.0/24 \
		    --INTERNET_INTERFACE "eth0" \
		    --PUBLIC_HOST_IP 10.0.1.2/24 \
		    --PRIVATE_HOST_IP 10.0.2.2/24 \
		    --FIREWALL_POLICY ~/private-policy.json

		echo "=== 🏗 Creating VPC B ==="
		sudo vpcctl create \
		    --VPC_NAME vpcB \
		    --CIDR_BLOCK 192.168.0.0/16 \
		    --PUBLIC_SUBNET 192.168.1.0/24 \
		    --PRIVATE_SUBNET 192.168.2.0/24 \
		    --INTERNET_INTERFACE "eth0" \
		    --PUBLIC_HOST_IP 192.168.1.2/24 \
		    --PRIVATE_HOST_IP 192.168.2.2/24 \
		    --FIREWALL_POLICY ~/private-policy.json




		#========================================
		# VPC A Testing
		#========================================
		echo "=== ✅ Verifying VPC A Setup ==="
		sudo ip netns list
		sudo ip link show type bridge
		sudo bridge link show

		sudo ip netns exec vpcA-public ip addr show vethA-pub
		sudo ip netns exec vpcA-private ip addr show vethA-pri

		sudo ip netns exec vpcA-public route -n
		sudo ip netns exec vpcA-private route -n

		echo "=== 🧪 Connectivity Tests ==="
		echo "--- 🔹 Public subnet tests ---"
		sudo ip netns exec vpcA-public ping -c 2 10.0.1.1
		sudo ip netns exec vpcA-public ping -c 2 10.0.2.2
		sudo ip netns exec vpcA-public ping -c 2 8.8.8.8 || echo "⚠  Public subnet external ping may fail"

		echo "--- 🔸 Private subnet tests ---"
		sudo ip netns exec vpcA-private ping -c 2 10.0.2.1
		sudo ip netns exec vpcA-private ping -c 2 10.0.1.2
		sudo ip netns exec vpcA-private ping -c 2 8.8.8.8 || echo "✅ Private subnet isolated"	
		#========================================
		# VPC B Testing
		#========================================
		echo "=== ✅ Verifying VPC B Setup ==="
		sudo ip netns list
		sudo ip link show type bridge
		sudo bridge link show

		sudo ip netns exec vpcB-public ip addr show vethB-pub
		sudo ip netns exec vpcB-private ip addr show vethB-pri

		sudo ip netns exec vpcB-public route -n
		sudo ip netns exec vpcB-private route -n

		echo "=== 🧪 Connectivity Tests ==="
		echo "--- 🔹 Public subnet tests ---"
		sudo ip netns exec vpcB-public ping -c 2 192.168.1.1
		sudo ip netns exec vpcB-public ping -c 2 192.168.2.2
		sudo ip netns exec vpcB-public ping -c 2 8.8.8.8 || echo "⚠  Public subnet external ping may fail"

		echo "--- 🔸 Private subnet tests ---"
		sudo ip netns exec vpcB-private ping -c 2 192.168.2.1
		sudo ip netns exec vpcB-private ping -c 2 192.168.1.2
		sudo ip netns exec vpcB-private ping -c 2 8.8.8.8 || echo "✅ Private subnet isolated"

		#========================================
		# Deploy Workload Servers
		#========================================
		echo "=== 🌐 Deploying workload servers ==="
		sudo vpcctl deploy-server --VPC_NAME vpcA --PUBLIC_IP 10.0.1.2 --PRIVATE_IP 10.0.2.2
		sudo vpcctl deploy-server --VPC_NAME vpcB --PUBLIC_IP 192.168.1.2 --PRIVATE_IP 192.168.2.2	

		#========================================
		# Workload Testing VPC A
		#========================================
		echo "=== 🌐 Testing Host Connectivity for VPC A ==="
		echo "Trying to reach PUBLIC subnet server (should succeed):"
		curl -s -m 3 http://10.0.1.2:8080 | grep "Public Subnet" >/dev/null && echo "✅ Host can reach Public server" || echo "❌ Cannot reach Public server"

		if ! curl -s -m 3 http://10.0.2.2:8080 >/dev/null; then
		    echo "✅ Host cannot reach Private server (expected)"
		else
		    echo "❌ Host can reach Private server (unexpected)"
		fi

		echo "=== 🧭 Cross-Namespace Connectivity ==="
		echo "From vpcA-public -> Private server:"
		sudo ip netns exec vpcA-public curl -s -m 3 http://10.0.2.2:8080 | grep "Private Subnet" >/dev/null && echo "✅ Public can reach Private" || echo "❌ Public cannot reach Private"

		echo "From vpcA-private -> Public server:"
		sudo ip netns exec vpcA-private curl -s -m 3 http://10.0.1.2:8080 | grep "Public Subnet" >/dev/null && echo "✅ Private can reach Public" || echo "❌ Private cannot reach Public"

		#========================================
		# Workload Testing VPC B
		#========================================
		echo "=== 🌐 Testing Host Connectivity for VPC B ==="
		echo "Trying to reach PUBLIC subnet server (should succeed):"
		curl -s -m 3 http://192.168.1.2:8080 | grep "Public Subnet" >/dev/null && echo "✅ Host can reach Public server" || echo "❌ Cannot reach Public server"

		if ! curl -s -m 3 http://192.168.2.2:8080 >/dev/null; then
		    echo "✅ Host cannot reach Private server (expected)"
		else
		    echo "❌ Host can reach Private server (unexpected)"
		fi


		echo "=== 🧭 Cross-Namespace Connectivity ==="
		echo "From vpcB-public -> Private server:"
		sudo ip netns exec vpcB-public curl -s -m 3 http://192.168.2.2:8080 | grep "Private Subnet" >/dev/null && echo "✅ Public can reach Private" || echo "❌ Public cannot reach Private"

		echo "From vpcB-private -> Public server:"
		sudo ip netns exec vpcB-private curl -s -m 3 http://192.168.1.2:8080 | grep "Public Subnet" >/dev/null && echo "✅ Private can reach Public" || echo "❌ Private cannot reach Public"	


		#========================================
		# Test before Peering VPCs (should fail)
		#========================================
		if sudo ip netns exec vpcA-public ping -c 2 192.168.1.2 >/dev/null 2>&1; then
			echo "❌ Unexpectedly reachable!"
		else
            		echo "✅ Isolation working as expected"
		fi

		if sudo ip netns exec vpcB-public ping -c 2 10.0.1.2 >/dev/null 2>&1; then
            		echo "❌ Unexpectedly reachable!"
		else
    				echo "✅ Isolation working as expected"
		fi

		#========================================
		# Peering VPCs
		#========================================
		echo "=== 🔗 Peering VPC A and VPC B ==="
		sudo vpcctl peer \
		    --VPC_A vpcA \
		    --VPC_B vpcB \
		    --PUBLIC_SUBNET_A 10.0.1.0/24 \
		    --PUBLIC_SUBNET_B 192.168.1.0/24


		#========================================
		# Test after Peering VPCs (should work)
		#========================================

		echo "=== 🧭 Testing connectivity after VPC peering ==="

		# From vpcA-public → vpcB-public
		if sudo ip netns exec vpcA-public ping -c 2 192.168.1.2 >/dev/null 2>&1; then
		    echo "✅ vpcA-public can reach vpcB-public (peering working)"
		else
		    echo "❌ vpcA-public cannot reach vpcB-public (peering failed)"
		fi

		# From vpcB-public → vpcA-public
		if sudo ip netns exec vpcB-public ping -c 2 10.0.1.2 >/dev/null 2>&1; then
		    echo "✅ vpcB-public can reach vpcA-public (peering working)"
		else
		    echo "❌ vpcB-public cannot reach vpcA-public (peering failed)"
		fi


		#========================================
		# Before Firewall rule creation
		#========================================
		sudo ip netns exec vpcB-public ping -c 2 8.8.8.8 || echo "⚠  Public subnet external ping blocked (expected)"

		#========================================
		# Firewall rule creation
		#========================================
		echo "=== 🚫 Blocking ICMP for VPC B ==="
		sudo vpcctl block-icmp --VPC_NAME vpcB --POLICY_FILE /home/joe/public_no_icmp.json


		#========================================
		# After Firewall rule creation
		#========================================
		sudo ip netns exec vpcB-public ping -c 2 8.8.8.8 || echo "⚠  Public subnet external ping blocked (expected)"

		echo "Testing done!"
