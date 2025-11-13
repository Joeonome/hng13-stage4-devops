# VPCCTL

`vpcctl` is a **command-line tool** for simulating and managing virtual private cloud (VPC) environments on Linux using network namespaces, bridges, and firewall policies. It allows you to **create VPCs, deploy workload servers, peer VPCs, and apply firewall rules** — all for testing and experimentation in isolated network environments.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Commands](#commands)
- [Examples](#examples)
- [Testing Connectivity](#testing-connectivity)
- [Teardown](#teardown)
- [License](#license)

---

## Features

- Create multiple VPCs with **public and private subnets**
- Deploy **workload servers** in VPCs
- Test **connectivity** between subnets and hosts
- Apply **firewall rules** and ICMP blocking
- Peer VPCs for cross-VPC communication
- Teardown VPCs cleanly
- Fully automated **namespace and bridge management**
- Direct CLI execution as `vpcctl`
- Optional run of setup (`makefile.sh`) or cleanup (`teardown.sh`) scripts

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

2. Make `vpcctl.py` executable and accessible system-wide:

```bash
chmod +x vpcctl.py
sudo mv vpcctl.py /usr/local/bin/vpcctl
```

> ✅ You can now run commands using `vpcctl` directly from any location.

3. Ensure you have required tools:

```bash
sudo apt install iproute2 bridge-utils iptables curl -y
```

4. (Optional) Run helper scripts in your project folder:

- **Setup:** `./makefile.sh`
- **Cleanup:** `./teardown.sh`

---

## Usage

Run `vpcctl --help` to see available commands:

```bash
vpcctl --help
```

Basic workflow:

1. **Create VPCs**
2. **Deploy workload servers**
3. **Test connectivity**
4. **Peer VPCs**
5. **Apply firewall rules**
6. **Teardown when done**

---

## Commands

### 1. Create a VPC

```bash
sudo vpcctl create   --VPC_NAME <vpc_name>   --CIDR_BLOCK <vpc_cidr>   --PUBLIC_SUBNET <public_cidr>   --PRIVATE_SUBNET <private_cidr>   --INTERNET_INTERFACE <interface>   --PUBLIC_HOST_IP <public_host_ip>   --PRIVATE_HOST_IP <private_host_ip>   --FIREWALL_POLICY <policy_file.json>
```

### 2. Deploy a workload server

```bash
sudo vpcctl deploy-server   --VPC_NAME <vpc_name>   --PUBLIC_IP <public_ip>   --PRIVATE_IP <private_ip>
```

### 3. Peer two VPCs

```bash
sudo vpcctl peer   --VPC_A <vpcA_name>   --VPC_B <vpcB_name>   --PUBLIC_SUBNET_A <public_subnet_A>   --PUBLIC_SUBNET_B <public_subnet_B>
```

### 4. Block ICMP for a VPC

```bash
sudo vpcctl block-icmp   --VPC_NAME <vpc_name>   --POLICY_FILE <policy_file.json>
```

### 5. Teardown VPCs

```bash
sudo vpcctl TEARDOWN_VPCS --VPC_NAME <vpc_name1> <vpc_name2> ...
```

### 6. Run project scripts

```bash
vpcctl run-script --file makefile.sh
vpcctl run-script --file teardown.sh
```

---

## Examples

### Create two VPCs:

```bash
sudo vpcctl create   --VPC_NAME vpcA   --CIDR_BLOCK 10.0.0.0/16   --PUBLIC_SUBNET 10.0.1.0/24   --PRIVATE_SUBNET 10.0.2.0/24   --INTERNET_INTERFACE eth0   --PUBLIC_HOST_IP 10.0.1.2/24   --PRIVATE_HOST_IP 10.0.2.2/24   --FIREWALL_POLICY ./private-policy.json

sudo vpcctl create   --VPC_NAME vpcB   --CIDR_BLOCK 192.168.0.0/16   --PUBLIC_SUBNET 192.168.1.0/24   --PRIVATE_SUBNET 192.168.2.0/24   --INTERNET_INTERFACE eth0   --PUBLIC_HOST_IP 192.168.1.2/24   --PRIVATE_HOST_IP 192.168.2.2/24   --FIREWALL_POLICY ./private-policy.json
```

### Deploy servers:

```bash
sudo vpcctl deploy-server --VPC_NAME vpcA --PUBLIC_IP 10.0.1.2 --PRIVATE_IP 10.0.2.2
sudo vpcctl deploy-server --VPC_NAME vpcB --PUBLIC_IP 192.168.1.2 --PRIVATE_IP 192.168.2.2
```

### Peer VPCs:

```bash
sudo vpcctl peer   --VPC_A vpcA   --VPC_B vpcB   --PUBLIC_SUBNET_A 10.0.1.0/24   --PUBLIC_SUBNET_B 192.168.1.0/24
```

### Block ICMP for VPC B:

```bash
sudo vpcctl block-icmp --VPC_NAME vpcB --POLICY_FILE ./public-no-icmp.json
```

### Teardown VPCs:

```bash
sudo vpcctl TEARDOWN_VPCS --VPC_NAME vpcA vpcB
```

### Run project scripts:

```bash
vpcctl run-script --file makefile.sh
vpcctl run-script --file teardown.sh
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.