#!/usr/bin/env bash
# E-Rakshak Dynamic Sandbox Host Provisioning Script
set -euo pipefail

echo '[*] Provisioning E-Rakshak Sandbox Host...'

# 1. Install prerequisites
apt-get update && apt-get install -y --no-install-recommends \
    strace \
    tcpdump \
    qemu-user-static \
    iptables \
    iproute2 \
    python3 \
    python3-pip \
    python3-venv

# 2. Create isolated non-root runner user
if ! id -u sandbox-runner >/dev/null 2>&1; then
    useradd -m -s /bin/bash sandbox-runner
fi

# 3. Setup host-only bridge for INetSim (192.168.100.0/24)
ip link add br-sandbox type bridge || true
ip addr add 192.168.100.1/24 dev br-sandbox || true
ip link set br-sandbox up || true

# 4. Configure iptables to block internet access & redirect to INetSim
iptables -F FORWARD || true
iptables -A FORWARD -i br-sandbox -o eth0 -j DROP
iptables -t nat -A PREROUTING -i br-sandbox -p udp --dport 53 -j DNAT --to-destination 192.168.100.2:53
iptables -t nat -A PREROUTING -i br-sandbox -p tcp --dport 80 -j DNAT --to-destination 192.168.100.2:80
iptables -t nat -A PREROUTING -i br-sandbox -p tcp --dport 443 -j DNAT --to-destination 192.168.100.2:443

# 5. Multi-arch rootfs provisioning
mkdir -p /opt/sandbox/rootfs/{arm,aarch64,mips,mipsel,riscv64}

echo '[+] Sandbox host provisioned successfully.'

