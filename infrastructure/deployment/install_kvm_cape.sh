#!/usr/bin/env bash
# infra/install_kvm_cape.sh
#
# Run THIS ON the GCP instance itself (after SSH-ing in via
# setup_gcp_vm.sh's output command) — installs KVM/QEMU and CAPE
# sandbox for Windows detonation, plus INetSim for network
# containment.
#
# Usage (on the instance):
#   chmod +x install_kvm_cape.sh
#   sudo ./install_kvm_cape.sh

set -euo pipefail

echo "=== Installing KVM/QEMU + libvirt ==="
sudo apt-get update
sudo apt-get install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils \
    virtinst virt-manager python3-pip python3-venv git

echo "=== Verifying nested virtualization is actually active ==="
if [ "$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || cat /sys/module/kvm_amd/parameters/nested 2>/dev/null)" != "Y" ]; then
    echo "WARNING: nested virtualization does not appear active. Confirm the VM was created with --enable-nested-virtualization (see setup_gcp_vm.sh)."
else
    echo "Nested virtualization confirmed active."
fi

echo "=== Adding current user to libvirt/kvm groups ==="
sudo usermod -aG libvirt "$(whoami)"
sudo usermod -aG kvm "$(whoami)"

echo "=== Installing INetSim (network sinkhole for contained detonation) ==="
sudo apt-get install -y inetsim

echo "=== Cloning CAPE sandbox ==="
if [ ! -d "/opt/CAPEv2" ]; then
    sudo git clone https://github.com/kevoreilly/CAPEv2.git /opt/CAPEv2
fi
cd /opt/CAPEv2

echo "=== Installing CAPE dependencies ==="
sudo python3 -m venv /opt/CAPEv2/venv
sudo /opt/CAPEv2/venv/bin/pip install -r requirements.txt

echo ""
echo "=== Done — manual steps still required ==="
echo "1. Log out and back in for group membership (libvirt/kvm) to take effect"
echo "2. Build the Windows 10 golden VM in virt-manager, install the CAPE agent inside it,"
echo "   take a clean snapshot — CAPE reverts to this snapshot after every detonation"
echo "3. Configure /opt/CAPEv2/conf/cape.conf to point at your golden snapshot"
echo "4. Configure INetSim (/etc/inetsim/inetsim.conf) to sinkhole all victim-VM traffic"
echo "5. Start CAPE: cd /opt/CAPEv2 && ./venv/bin/python3 cape.py"