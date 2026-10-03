#!/usr/bin/env bash
# infra/setup_gcp_vm.sh
#
# Creates the GCP detonation-plane VM: nested virtualization enabled,
# n2-standard-4, Mumbai region. Run once per environment setup.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (`gcloud auth login`)
#   - A GCP project already created (or edit PROJECT_ID below)
#
# Usage:
#   chmod +x infra/setup_gcp_vm.sh
#   ./infra/setup_gcp_vm.sh

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-ps4-malware-suite}"
INSTANCE_NAME="${GCP_VM_INSTANCE_NAME:-ps4-detonation-sandbox}"
ZONE="asia-south1-a"
MACHINE_TYPE="n2-standard-4"
BOOT_DISK_SIZE="100GB"
IMAGE_FAMILY="ubuntu-2204-lts"
IMAGE_PROJECT="ubuntu-os-cloud"

echo "=== SentinelScan — GCP Detonation Plane Setup ==="
echo "Project:  ${PROJECT_ID}"
echo "Instance: ${INSTANCE_NAME}"
echo "Zone:     ${ZONE}"
echo ""

echo "[1/4] Setting active project..."
gcloud config set project "${PROJECT_ID}"

echo "[2/4] Enabling Compute Engine API..."
gcloud services enable compute.googleapis.com

echo "[3/4] Creating VM with nested virtualization enabled..."
gcloud compute instances create "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --machine-type="${MACHINE_TYPE}" \
    --image-family="${IMAGE_FAMILY}" \
    --image-project="${IMAGE_PROJECT}" \
    --boot-disk-size="${BOOT_DISK_SIZE}" \
    --enable-nested-virtualization \
    --tags=sentinelscan-sandbox

echo "[4/4] Configuring firewall — SSH only, no other public ports..."
gcloud compute firewall-rules create sentinelscan-ssh-only \
    --allow=tcp:22 \
    --target-tags=sentinelscan-sandbox \
    --description="SSH-only access to detonation sandbox. Control Plane (dashboard/API) is a separate instance and handles its own port 443." \
    || echo "Firewall rule already exists, skipping."

echo ""
echo "=== Done ==="
echo "SSH in with:"
echo "  gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE}"
echo ""
echo "Next step: run infra/install_kvm_cape.sh on the instance itself."