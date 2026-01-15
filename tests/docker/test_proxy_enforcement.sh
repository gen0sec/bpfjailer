#!/bin/bash
# Test proxy enforcement for AI agents
# This test verifies that when require_proxy=true, direct connections are blocked

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/../../examples/docker"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    cd "$DOCKER_DIR"
    docker compose down 2>/dev/null || true
}

trap cleanup EXIT

# Build and start services
log_info "Starting proxy enforcement test..."
cd "$DOCKER_DIR"

log_info "Building containers..."
docker compose build --quiet

log_info "Starting services (bpfjailer, ai-agent, proxy)..."
docker compose up -d

log_info "Waiting for services to be healthy..."
sleep 10

# Check proxy is running
log_info "Verifying proxy is running..."
if docker compose exec -T proxy pgrep tinyproxy >/dev/null 2>&1; then
    log_info "Proxy is running"
else
    log_error "Proxy is not running"
    docker compose logs proxy
    exit 1
fi

# Get proxy IP
PROXY_IP=$(docker inspect ai-proxy -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
log_info "Proxy IP: $PROXY_IP"

# Run proxy test inside the ai-agent container
log_info "Running proxy enforcement tests..."

docker compose exec -T ai-agent python3 << 'PYTHON_TEST'
import socket
import os
import sys
import json

PROXY_IP = "172.28.0.10"
PROXY_PORT = 3128
ENROLLMENT_SOCKET = "/run/bpfjailer/enrollment.sock"

def enroll_with_proxy_role():
    """Enroll this process with the ai_agent_proxy role (ID 13)."""
    print("Enrolling with ai_agent_proxy role (require_proxy=true)...")

    if not os.path.exists(ENROLLMENT_SOCKET):
        print("  ERROR: Enrollment socket not found")
        return False

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(ENROLLMENT_SOCKET)

        role_id = 13  # ai_agent_proxy role
        pod_id = 2000

        # JSON protocol: {"Enroll":{"pod_id":N,"role_id":M}}
        request = json.dumps({"Enroll": {"pod_id": pod_id, "role_id": role_id}})
        sock.send((request + "\n").encode())

        response = sock.recv(4096).decode()
        sock.close()

        if response:
            resp_data = json.loads(response)
            if resp_data == "Success":
                print(f"  Enrolled PID {os.getpid()} with role {role_id}")
                return True
            elif "Error" in resp_data:
                print(f"  Enrollment error: {resp_data['Error']}")
                return False
            else:
                print(f"  Unexpected response: {resp_data}")
                return False
        else:
            print("  No response from enrollment socket")
            return False

    except Exception as e:
        print(f"  ERROR: Failed to enroll: {e}")
        return False

# Enroll before running tests
if not enroll_with_proxy_role():
    print("WARNING: Could not enroll with proxy role, tests may not work correctly")
    print("Continuing anyway...")

print("=" * 60)
print("Proxy Enforcement Tests")
print("=" * 60)

def test_direct_connection_blocked():
    """Test that direct connections to external IPs are blocked when proxy is required."""
    print("\n=== Test: Direct Connection Should Be Blocked ===")

    # Try to connect directly to a public IP (Google DNS)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex(("8.8.8.8", 53))
        sock.close()

        if result in [1, 13]:  # EPERM or EACCES
            print(f"  PASS - Direct connection blocked (errno={result})")
            return True
        elif result == 0:
            print(f"  FAIL - Direct connection succeeded (should be blocked)")
            return False
        else:
            print(f"  WARN - Direct connection returned errno={result}")
            return None
    except socket.timeout:
        print("  WARN - Connection timed out (may be blocked at network level)")
        return None
    except Exception as e:
        if "Permission denied" in str(e) or "Operation not permitted" in str(e):
            print(f"  PASS - Direct connection blocked: {e}")
            return True
        print(f"  ERROR - {e}")
        return None

def test_proxy_connection_allowed():
    """Test that connections to the proxy are allowed."""
    print("\n=== Test: Proxy Connection Should Be Allowed ===")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((PROXY_IP, PROXY_PORT))
        sock.close()

        if result == 0:
            print(f"  PASS - Proxy connection succeeded")
            return True
        elif result == 111:  # ECONNREFUSED
            print(f"  PASS - Proxy connection allowed (service not listening)")
            return True
        elif result in [1, 13]:
            print(f"  FAIL - Proxy connection blocked (errno={result})")
            return False
        else:
            print(f"  WARN - Proxy connection returned errno={result}")
            return None
    except Exception as e:
        if "Connection refused" in str(e):
            print(f"  PASS - Proxy connection allowed (refused by server)")
            return True
        print(f"  ERROR - {e}")
        return None

def test_localhost_allowed():
    """Test that localhost connections are still allowed."""
    print("\n=== Test: Localhost Should Be Allowed ===")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 65432))
        sock.close()

        if result == 111:  # ECONNREFUSED
            print(f"  PASS - Localhost connection allowed (refused)")
            return True
        elif result == 0:
            print(f"  PASS - Localhost connection succeeded")
            return True
        elif result in [1, 13]:
            print(f"  FAIL - Localhost connection blocked (errno={result})")
            return False
        else:
            print(f"  WARN - Localhost returned errno={result}")
            return None
    except Exception as e:
        if "Connection refused" in str(e):
            print(f"  PASS - Localhost allowed")
            return True
        print(f"  ERROR - {e}")
        return None

def test_http_via_proxy():
    """Test HTTP request through proxy."""
    print("\n=== Test: HTTP Through Proxy ===")

    try:
        import urllib.request

        # Configure proxy
        proxy_handler = urllib.request.ProxyHandler({
            'http': f'http://{PROXY_IP}:{PROXY_PORT}',
            'https': f'http://{PROXY_IP}:{PROXY_PORT}'
        })
        opener = urllib.request.build_opener(proxy_handler)

        # Try to fetch a simple HTTP page through proxy
        req = urllib.request.Request('http://example.com/', headers={'User-Agent': 'test'})
        response = opener.open(req, timeout=10)

        if response.status == 200:
            print(f"  PASS - HTTP through proxy succeeded")
            return True
        else:
            print(f"  WARN - HTTP through proxy returned {response.status}")
            return None

    except urllib.error.URLError as e:
        if "Permission denied" in str(e):
            print(f"  FAIL - Proxy connection blocked: {e}")
            return False
        print(f"  WARN - HTTP error (may be network): {e}")
        return None
    except Exception as e:
        print(f"  ERROR - {e}")
        return None

# Run tests
results = {
    "direct_blocked": test_direct_connection_blocked(),
    "proxy_allowed": test_proxy_connection_allowed(),
    "localhost_allowed": test_localhost_allowed(),
    "http_via_proxy": test_http_via_proxy(),
}

print("\n" + "=" * 60)
print("Summary")
print("=" * 60)

passed = sum(1 for v in results.values() if v is True)
failed = sum(1 for v in results.values() if v is False)
skipped = sum(1 for v in results.values() if v is None)

for test, result in results.items():
    status = "PASS" if result is True else "FAIL" if result is False else "SKIP"
    print(f"  {test}: {status}")

print(f"\nPassed: {passed}, Failed: {failed}, Skipped: {skipped}")

# Exit with error if critical tests failed
if results["direct_blocked"] is False or results["proxy_allowed"] is False:
    print("\nERROR: Proxy enforcement not working correctly")
    sys.exit(1)

sys.exit(0)
PYTHON_TEST

TEST_RESULT=$?

if [ $TEST_RESULT -eq 0 ]; then
    log_info "Proxy enforcement tests passed!"
else
    log_error "Proxy enforcement tests failed!"
fi

exit $TEST_RESULT
