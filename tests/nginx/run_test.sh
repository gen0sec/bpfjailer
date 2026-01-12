#!/bin/bash
# Test script demonstrating BpfJailer policy enforcement on nginx

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "BpfJailer nginx Policy Test"
echo "=========================================="
echo ""
echo "webserver_test role (ID 8) allows: TCP 80, 443, 8080"
echo ""

# Check if daemon is running
if [ ! -S /run/bpfjailer/enrollment.sock ]; then
    echo "ERROR: BpfJailer daemon not running"
    echo "Start with: sudo RUST_LOG=info ./target/release/bpfjailer-daemon"
    exit 1
fi

run_nginx_test() {
    local config=$1
    local description=$2
    local role_id=${3:-8}

    echo "----------------------------------------"
    echo "TEST: $description"
    echo "Config: $config"
    echo "Role ID: $role_id"
    echo "----------------------------------------"

    # Enroll and run nginx using nginx.py
    python3 "$SCRIPT_DIR/nginx.py" "$config" "$role_id" 2>&1 &
    local pid=$!
    sleep 1

    # Check if nginx is still running
    if kill -0 $pid 2>/dev/null; then
        echo "RESULT: nginx started successfully"
        kill $pid 2>/dev/null
        wait $pid 2>/dev/null
    else
        echo "RESULT: nginx failed to start (blocked by BpfJailer)"
    fi
    echo ""
}

echo ""
echo "TEST 1: Port 8080 - ALLOWED"
run_nginx_test "$SCRIPT_DIR/nginx_allow.conf" "Port 8080 (allowed)"

sleep 1

echo ""
echo "TEST 2: Port 9000 - BLOCKED"
run_nginx_test "$SCRIPT_DIR/nginx_blocked.conf" "Port 9000 (blocked)"

echo "=========================================="
echo "Test complete"
echo "=========================================="
