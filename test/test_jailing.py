#!/usr/bin/env python3
"""
BpfJailer Jailing Test Script

Tests the enrollment and jailing functionality:
- Restricted role (ID 1): blocks file, network, exec
- Permissive role (ID 2): allows file, network, exec

Usage:
    sudo python3 test_jailing.py [-v|--verbose]

Options:
    -v, --verbose    Show detailed test output
"""

import socket
import json
import os
import sys
import subprocess
import tempfile

SOCKET_PATH = "/run/bpfjailer/enrollment.sock"

def is_verbose():
    return "-v" in sys.argv or "--verbose" in sys.argv or os.environ.get("VERBOSE") == "1"

def enroll(pod_id: int, role_id: int) -> bool:
    """Enroll current process into a pod with given role."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(SOCKET_PATH)
        request = {"Enroll": {"pod_id": pod_id, "role_id": role_id}}
        sock.send((json.dumps(request) + "\n").encode())
        response = sock.recv(4096).decode().strip()
        sock.close()
        return "Success" in response
    except Exception as e:
        print(f"  Enrollment error: {e}")
        return False

def test_file_read(path: str = "/etc/passwd") -> bool:
    """Test if file read is allowed."""
    try:
        with open(path, "r") as f:
            f.read(10)
        return True
    except (PermissionError, OSError):
        return False

def test_file_write() -> bool:
    """Test if file write is allowed."""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
            f.write("test")
        return True
    except (PermissionError, OSError):
        return False

def test_socket_connect(port: int = 1) -> bool:
    """Test if socket connect is allowed to a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        # Try to connect to localhost (will fail but tests if syscall is allowed)
        sock.connect(("127.0.0.1", port))
        sock.close()
        return True
    except ConnectionRefusedError:
        # Connection refused means syscall was allowed
        return True
    except (PermissionError, OSError) as e:
        if "Permission denied" in str(e) or e.errno == 13:
            return False
        # Other errors (like timeout) mean syscall was allowed
        return True

def test_socket_bind(port: int = 0) -> bool:
    """Test if socket bind is allowed to a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.close()
        return True
    except (PermissionError, OSError) as e:
        if "Permission denied" in str(e) or e.errno == 13:
            return False
        # Address already in use or other errors mean syscall was allowed
        return True

def test_exec() -> bool:
    """Test if exec is allowed."""
    try:
        result = subprocess.run(["/bin/true"], capture_output=True, timeout=1)
        return result.returncode == 0
    except (PermissionError, OSError):
        return False
    except subprocess.TimeoutExpired:
        return True  # Timeout means exec was allowed

def run_test(name: str, test_func, expected: bool) -> bool:
    """Run a test and report result."""
    result = test_func()
    passed = result == expected
    status = "PASS" if passed else "FAIL"
    expected_str = "allowed" if expected else "blocked"
    actual_str = "allowed" if result else "blocked"

    # Always show test results
    print(f"  [{status}] {name}: {actual_str} (expected {expected_str})", flush=True)

    return passed

def test_restricted_role():
    """Test restricted role (ID 1) - should block everything."""
    sys.stdout.flush()

    # Fork a new process to test (so we don't jail the test script itself)
    pid = os.fork()
    if pid == 0:
        # Child process
        if not enroll(pod_id=1000, role_id=1):
            print("  [FAIL] Enrollment failed", flush=True)
            os._exit(1)

        # file_open will trigger pending enrollment migration automatically
        all_passed = True
        all_passed &= run_test("File read", test_file_read, expected=False)
        all_passed &= run_test("File write", test_file_write, expected=False)

        os._exit(0 if all_passed else 1)
    else:
        # Parent waits for child
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def test_permissive_role():
    """Test permissive role (ID 2) - should allow everything."""
    sys.stdout.flush()

    pid = os.fork()
    if pid == 0:
        # Child process
        if not enroll(pod_id=2000, role_id=2):
            print("  [FAIL] Enrollment failed", flush=True)
            os._exit(1)

        all_passed = True
        all_passed &= run_test("File read", test_file_read, expected=True)
        all_passed &= run_test("File write", test_file_write, expected=True)

        os._exit(0 if all_passed else 1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def test_network_control():
    """Test that network operations are controlled by jailing."""
    sys.stdout.flush()

    pid = os.fork()
    if pid == 0:
        # Child process - enroll as restricted
        if not enroll(pod_id=4000, role_id=1):
            print("  [FAIL] Enrollment failed", flush=True)
            os._exit(1)

        # Trigger migration
        try:
            open("/dev/null", "r")
        except:
            pass

        # Test network connect - should be blocked for restricted role
        can_connect = test_socket_connect(80)
        if not can_connect:
            print("  [PASS] TCP connect blocked", flush=True)
            os._exit(0)
        else:
            print("  [FAIL] TCP connect allowed (should be blocked)", flush=True)
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def test_inheritance():
    """Test that children inherit the jail from parent."""
    sys.stdout.flush()

    pid = os.fork()
    if pid == 0:
        # Child process - enroll as restricted
        if not enroll(pod_id=3000, role_id=1):
            print("  [FAIL] Parent enrollment failed", flush=True)
            os._exit(1)

        # Trigger migration by doing a file_open syscall
        try:
            with open("/dev/null", "r") as f:
                pass
        except:
            pass  # Expected to fail if restricted

        # Verify parent is restricted
        parent_can_read = test_file_read()
        if parent_can_read:
            print("  [WARN] Parent not restricted", flush=True)
            os._exit(1)

        # Now fork a grandchild
        sys.stdout.flush()
        grandchild_pid = os.fork()
        if grandchild_pid == 0:
            # Grandchild - should inherit restriction via task_alloc
            can_read = test_file_read()
            if not can_read:
                print("  [PASS] Child inherited restriction", flush=True)
                os._exit(0)
            else:
                print("  [FAIL] Child NOT restricted", flush=True)
                os._exit(1)
        else:
            _, status = os.waitpid(grandchild_pid, 0)
            os._exit(os.WEXITSTATUS(status))
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def test_webserver_role():
    """Test webserver role (ID 3) - file and network allowed, network rules applied."""
    sys.stdout.flush()

    pid = os.fork()
    if pid == 0:
        # Child process
        if not enroll(pod_id=5000, role_id=3):
            print("  [FAIL] Enrollment failed", flush=True)
            os._exit(1)

        # Trigger migration
        try:
            open("/dev/null", "r")
        except:
            pass

        all_passed = True

        # Webserver role has allow_file_access=true
        all_passed &= run_test("File read", test_file_read, expected=True)

        # Webserver role has allow_network=true with specific port rules
        # Port 80 should be allowed (in policy)
        all_passed &= run_test("TCP connect to port 80", lambda: test_socket_connect(80), expected=True)

        # Port 443 should be allowed (in policy)
        all_passed &= run_test("TCP connect to port 443", lambda: test_socket_connect(443), expected=True)

        os._exit(0 if all_passed else 1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def vprint(*args, **kwargs):
    """Print only in verbose mode."""
    if is_verbose():
        print(*args, flush=True, **kwargs)

def test_unenrolled():
    """Test that unenrolled processes are not restricted."""
    sys.stdout.flush()

    pid = os.fork()
    if pid == 0:
        # Child process - don't enroll
        all_passed = True
        all_passed &= run_test("File read", test_file_read, expected=True)
        all_passed &= run_test("File write", test_file_write, expected=True)

        os._exit(0 if all_passed else 1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def check_daemon():
    """Check if daemon is running."""
    if not os.path.exists(SOCKET_PATH):
        print(f"ERROR: Daemon socket not found at {SOCKET_PATH}")
        print("Start the daemon first: sudo ./target/release/bpfjailer-daemon")
        return False
    return True

def main():
    # Set verbose env var so forked children inherit it
    if "-v" in sys.argv or "--verbose" in sys.argv:
        os.environ["VERBOSE"] = "1"

    # Make stdout unbuffered to avoid duplicate output in forked processes
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

    print("=" * 50)
    print("BpfJailer Jailing Test Suite")
    print("=" * 50)

    if os.geteuid() != 0:
        print("ERROR: This test must be run as root")
        sys.exit(1)

    if not check_daemon():
        sys.exit(1)

    results = []

    print("\n[1/4] Unenrolled process (should allow all)")
    results.append(("Unenrolled process", test_unenrolled()))

    print("\n[2/4] Restricted role (should block all)")
    results.append(("Restricted role", test_restricted_role()))

    print("\n[3/4] Permissive role (should allow all)")
    results.append(("Permissive role", test_permissive_role()))

    print("\n[4/6] Inheritance (child inherits parent's jail)")
    results.append(("Inheritance", test_inheritance()))

    print("\n[5/6] Network control (bind/connect blocked for restricted)")
    results.append(("Network control", test_network_control()))

    print("\n[6/6] Webserver role (from policy.json, network rules)")
    results.append(("Webserver role", test_webserver_role()))

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)

    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
        all_passed &= passed

    print()
    if all_passed:
        print("All tests PASSED!")
        sys.exit(0)
    else:
        print("Some tests FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    main()
