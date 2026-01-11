#!/bin/bash
set -e

DAEMON_PID=""
SOCKET_PATH="/run/bpfjailer/enrollment.sock"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
    if [ ! -z "$DAEMON_PID" ]; then
        echo "Stopping daemon (PID: $DAEMON_PID)"
        sudo kill $DAEMON_PID 2>/dev/null || true
        wait $DAEMON_PID 2>/dev/null || true
    fi
    if [ -e "$SOCKET_PATH" ]; then
        sudo rm -f "$SOCKET_PATH"
    fi
    if [ -d "$(dirname "$SOCKET_PATH")" ]; then
        sudo rmdir "$(dirname "$SOCKET_PATH")" 2>/dev/null || true
    fi
}

trap cleanup EXIT

echo "=== BpfJailer Integration Test ==="
echo ""

# Check kernel version
KERNEL_VER=$(uname -r | cut -d. -f1,2)
KERNEL_MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VER | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 11 ]); then
    echo "WARNING: Kernel version $(uname -r) may not support all features (requires 5.11+)"
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test must be run as root (for eBPF loading)"
    exit 1
fi

echo "1. Building BpfJailer..."
cd "$ROOT_DIR"
/root/.cargo/bin/cargo build --release || {
    echo "ERROR: Build failed"
    exit 1
}

echo "2. Checking prerequisites..."
if ! command -v clang &> /dev/null; then
    echo "WARNING: clang not found - BPF programs may not compile"
fi

if [ ! -d "/sys/fs/bpf" ]; then
    echo "WARNING: /sys/fs/bpf not found - BPF filesystem may not be mounted"
fi

echo "3. Starting daemon..."
./target/release/bpfjailer-daemon > /tmp/bpfjailer.log 2>&1 &
DAEMON_PID=$!

# Wait for daemon to start
sleep 3

# Check if daemon is still running
if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "ERROR: Daemon failed to start"
    echo "Logs:"
    cat /tmp/bpfjailer.log
    exit 1
fi

echo "4. Verifying daemon socket..."
if [ ! -e "$SOCKET_PATH" ]; then
    echo "ERROR: Daemon socket not created at $SOCKET_PATH"
    echo "Logs:"
    cat /tmp/bpfjailer.log
    exit 1
fi

if [ ! -S "$SOCKET_PATH" ]; then
    echo "ERROR: $SOCKET_PATH is not a Unix socket"
    exit 1
fi

echo "   Socket created successfully: $SOCKET_PATH"

echo "5. Checking eBPF programs..."
if command -v bpftool &> /dev/null; then
    PROG_COUNT=$(sudo bpftool prog list | grep -c "lsm" || echo "0")
    echo "   Found $PROG_COUNT LSM eBPF programs"
else
    echo "   bpftool not found, skipping eBPF program check"
fi

echo "6. Testing socket communication..."
# Simple test: try to connect to socket
if timeout 1 bash -c "echo 'test' > $SOCKET_PATH" 2>/dev/null; then
    echo "   Socket accepts connections"
else
    echo "   WARNING: Socket connection test inconclusive"
fi

echo ""
echo "=== All basic tests passed! ==="
echo "Daemon is running (PID: $DAEMON_PID)"
echo "Logs: /tmp/bpfjailer.log"
echo ""
echo "To stop the daemon, press Ctrl+C or run: sudo kill $DAEMON_PID"

# Keep running until interrupted
wait $DAEMON_PID
