#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="/var/lib/libvirt/images/bpfjailer-test"
VM_NAME="bpfjailer-test"

echo "=== BpfJailer Libvirt Test ==="

# Check VM is defined
if ! virsh dominfo ${VM_NAME} &>/dev/null; then
    echo "Error: VM not defined. Run ./setup_vm.sh first"
    exit 1
fi

# Copy binaries to share
echo "[1/4] Copying binaries..."
BOOTSTRAP_BIN="${SCRIPT_DIR}/../../target/release/bpfjailer-bootstrap"
BPF_OBJ="${SCRIPT_DIR}/../../bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"

if [ ! -f "$BOOTSTRAP_BIN" ]; then
    echo "Error: Bootstrap binary not found. Build with: cargo build -p bpfjailer-bootstrap --release"
    exit 1
fi

if [ ! -f "$BPF_OBJ" ]; then
    echo "Error: BPF object not found at $BPF_OBJ"
    exit 1
fi

cp "$BOOTSTRAP_BIN" "${VM_DIR}/share/"
cp "$BPF_OBJ" "${VM_DIR}/share/"
echo "  Copied bootstrap and BPF object to share/"

# Start VM if not running
echo "[2/4] Starting VM..."
if virsh domstate ${VM_NAME} 2>/dev/null | grep -q running; then
    echo "  VM already running"
else
    virsh start ${VM_NAME}
fi

# Wait for VM to boot
echo "[3/4] Waiting for VM to boot..."
for i in {1..60}; do
    IP=$(virsh domifaddr ${VM_NAME} 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    if [ -n "$IP" ]; then
        echo "  VM IP: $IP"
        break
    fi
    sleep 2
done

if [ -z "$IP" ]; then
    echo "  Waiting for cloud-init (no IP yet)..."
    sleep 30
    IP=$(virsh domifaddr ${VM_NAME} 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
fi

if [ -z "$IP" ]; then
    echo "Error: Could not get VM IP. Try: virsh console ${VM_NAME}"
    exit 1
fi

# Wait for SSH
echo "  Waiting for SSH..."
for i in {1..30}; do
    if nc -z -w1 "$IP" 22 2>/dev/null; then
        break
    fi
    sleep 2
done

sleep 5  # Extra time for SSH to be fully ready

# Run test
echo "[4/4] Running bootstrap test..."
sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@${IP} << 'REMOTE'
echo "=== Inside VM ==="

# Mount 9p share
sudo mkdir -p /mnt/share
sudo mount -t 9p -o trans=virtio share /mnt/share 2>/dev/null || true

# Install binaries
sudo mkdir -p /usr/lib/bpfjailer /usr/sbin
sudo cp /mnt/share/bpfjailer-bootstrap /usr/sbin/
sudo cp /mnt/share/bpfjailer.bpf.o /usr/lib/bpfjailer/
sudo chmod +x /usr/sbin/bpfjailer-bootstrap

echo "[1] BPF LSM status:"
cat /sys/kernel/security/lsm

echo "[2] Running bootstrap..."
sudo RUST_LOG=info /usr/sbin/bpfjailer-bootstrap

echo "[3] Pinned BPF objects:"
ls -la /sys/fs/bpf/bpfjailer/ 2>/dev/null || echo "None pinned"

echo "=== Test Complete ==="
REMOTE

echo ""
echo "VM still running. Commands:"
echo "  virsh console ${VM_NAME}  # Connect to console"
echo "  virsh destroy ${VM_NAME}  # Stop VM"
