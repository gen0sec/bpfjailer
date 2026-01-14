#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="/var/lib/libvirt/images/bpfjailer-test"
VM_NAME="bpfjailer-test"

echo "=== BpfJailer Libvirt Test (Headless) ==="

# Check VM is defined
if ! virsh dominfo ${VM_NAME} &>/dev/null; then
    echo "Error: VM not defined. Run ./setup_vm.sh first"
    exit 1
fi

# Copy binaries to share
echo "[1/5] Copying binaries..."
BOOTSTRAP_BIN="${SCRIPT_DIR}/../../target/release/bpfjailer-bootstrap"
BPF_OBJ="${SCRIPT_DIR}/../../bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"

if [ ! -f "$BOOTSTRAP_BIN" ]; then
    echo "Error: Bootstrap binary not found"
    exit 1
fi

mkdir -p "${VM_DIR}/share"
cp "$BOOTSTRAP_BIN" "${VM_DIR}/share/"
cp "$BPF_OBJ" "${VM_DIR}/share/"

# Stop VM if running
virsh destroy ${VM_NAME} 2>/dev/null || true
sleep 2

# Start VM
echo "[2/5] Starting VM..."
virsh start ${VM_NAME}

# Wait for IP
echo "[3/5] Waiting for VM to boot..."
IP=""
for i in {1..90}; do
    IP=$(virsh domifaddr ${VM_NAME} 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    if [ -n "$IP" ]; then
        echo "  VM IP: $IP"
        break
    fi
    sleep 2
done

if [ -z "$IP" ]; then
    echo "Error: VM did not get IP in time"
    virsh destroy ${VM_NAME} 2>/dev/null || true
    exit 1
fi

# Wait for SSH
echo "[4/5] Waiting for SSH..."
for i in {1..30}; do
    if sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 ubuntu@${IP} echo "SSH ready" 2>/dev/null; then
        break
    fi
    sleep 2
done

# Run test
echo "[5/5] Running bootstrap test..."
sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@${IP} << 'REMOTE'
echo "=== Inside VM ==="

# Mount share
sudo mkdir -p /mnt/share
sudo mount -t 9p -o trans=virtio share /mnt/share 2>/dev/null || true

# Install
sudo mkdir -p /usr/lib/bpfjailer /usr/sbin
sudo cp /mnt/share/bpfjailer-bootstrap /usr/sbin/
sudo cp /mnt/share/bpfjailer.bpf.o /usr/lib/bpfjailer/
sudo chmod +x /usr/sbin/bpfjailer-bootstrap

echo "[Test 1] BPF LSM status:"
cat /sys/kernel/security/lsm
if ! grep -q bpf /sys/kernel/security/lsm; then
    echo "WARNING: BPF LSM not enabled. Reboot required."
fi

echo "[Test 2] Kernel BTF:"
ls -la /sys/kernel/btf/vmlinux

echo "[Test 3] Running bootstrap..."
sudo RUST_LOG=info /usr/sbin/bpfjailer-bootstrap

echo "[Test 4] Pinned objects:"
ls -la /sys/fs/bpf/bpfjailer/ 2>/dev/null || echo "None"

echo "=== Test Complete ==="
REMOTE

RESULT=$?

# Cleanup
echo "Stopping VM..."
virsh destroy ${VM_NAME} 2>/dev/null || true

if [ $RESULT -eq 0 ]; then
    echo "Done! Test passed."
else
    echo "Test failed."
    exit 1
fi
