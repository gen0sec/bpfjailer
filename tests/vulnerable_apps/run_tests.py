#!/usr/bin/env python3
"""
BpfJailer Security Test Runner

Runs all vulnerable app tests with different BpfJailer roles
to demonstrate how each policy mitigates different attacks.

Usage:
    sudo python3 run_tests.py [--role ROLE_ID] [--test TEST_NAME]

Examples:
    sudo python3 run_tests.py                    # Run all tests without jailing
    sudo python3 run_tests.py --role 1           # Run all tests with restricted role
    sudo python3 run_tests.py --role 3           # Run all tests with webserver role
    sudo python3 run_tests.py --test path        # Run only path traversal test
"""
import socket
import json
import os
import sys
import subprocess
import argparse

SOCKET_PATH = "/run/bpfjailer/enrollment.sock"

TESTS = [
    ("path_traversal", "Path Traversal / Arbitrary File Read"),
    ("command_injection", "Command Injection"),
    ("reverse_shell", "Reverse Shell / Data Exfiltration"),
    ("ssrf", "Server-Side Request Forgery"),
    ("arbitrary_write", "Arbitrary File Write"),
    ("crypto_miner", "Crypto Miner / Resource Abuse"),
    ("privilege_escalation", "Privilege Escalation"),
    ("path_access", "Path-based Access Control"),
    ("wildcard_access", "Wildcard Path Matching"),
    ("auto_enrollment", "Auto-Enrollment Methods"),
    ("tee_protection", "TEE Protection (ptrace, module, BPF blocking)"),
    ("ai_agent_egress", "AI Agent Egress Control (IP/domain filtering)"),
    ("ai_agent_secrets", "AI Agent Secrets Protection"),
]

ROLES = {
    0: ("unenrolled", "No jailing - all operations allowed"),
    1: ("restricted", "Blocks file, network, and exec"),
    2: ("permissive", "Allows file, network, and exec"),
    3: ("webserver", "Allows file, network (ports 80,443,8080), blocks exec"),
    4: ("database", "Allows file, network (ports 5432,6379), blocks exec"),
    5: ("isolated", "Allows file, blocks network and exec"),
    6: ("web_with_db", "Web + DB ports (80,443,5432,3306,6379), blocks exec"),
    7: ("worker", "Allows exec + limited network (443,5432,6379,5672)"),
    9: ("sandbox", "Allows file, blocks network and exec (sandboxed processing)"),
    10: ("wildcard_test", "Tests wildcard path matching rules"),
    11: ("tee_protected", "TEE: blocks ptrace, module load, BPF operations"),
    12: ("ai_agent", "AI Agent: secrets protection, IP/domain filtering, proxy enforcement"),
}

def enroll(pod_id: int, role_id: int) -> bool:
    """Enroll current process with given role."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(SOCKET_PATH)
        request = {"Enroll": {"pod_id": pod_id, "role_id": role_id}}
        sock.send((json.dumps(request) + "\n").encode())
        response = sock.recv(4096).decode().strip()
        sock.close()
        return "Success" in response
    except Exception as e:
        print(f"Enrollment error: {e}")
        return False

def run_test(test_name: str, role_id: int = 0) -> bool:
    """Run a test with optional enrollment."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_script = os.path.join(script_dir, f"{test_name}.py")

    if not os.path.exists(test_script):
        print(f"Test script not found: {test_script}")
        return False

    # Read script content before forking (in case enrollment blocks file access)
    with open(test_script, 'r') as f:
        script_content = f.read()

    # Flush stdout before fork
    sys.stdout.flush()

    pid = os.fork()
    if pid == 0:
        # Child process - make stdout unbuffered
        sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

        if role_id > 0:
            # Enroll with the specified role
            if not enroll(pod_id=10000 + role_id, role_id=role_id):
                print(f"Failed to enroll with role {role_id}")
                sys.stdout.flush()
                os._exit(1)

            # Trigger enrollment migration by attempting file access
            try:
                open("/dev/null", "r")
            except:
                pass  # Expected if file access is blocked

        # Execute the test script content directly (already read before enrollment)
        try:
            # Create a proper globals dict with common imports
            test_globals = {
                '__name__': '__main__',
                '__builtins__': __builtins__,
            }
            exec(compile(script_content, test_script, 'exec'), test_globals)
            sys.stdout.flush()
            os._exit(0)
        except SystemExit as e:
            sys.stdout.flush()
            os._exit(e.code if isinstance(e.code, int) else 1)
        except Exception as e:
            print(f"Test error: {e}")
            sys.stdout.flush()
            os._exit(1)
    else:
        # Parent waits
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0

def check_daemon():
    """Check if daemon is running."""
    return os.path.exists(SOCKET_PATH)

def main():
    parser = argparse.ArgumentParser(description="BpfJailer Security Test Runner")
    parser.add_argument("--role", type=int, default=0,
                        help="Role ID to use (0=unenrolled, 1=restricted, 2=permissive, 3=webserver, 5=isolated)")
    parser.add_argument("--test", type=str, default=None,
                        help="Run specific test (path, cmd, shell, ssrf, write, miner, privesc)")
    parser.add_argument("--list", action="store_true",
                        help="List available tests and roles")
    args = parser.parse_args()

    if args.list:
        print("Available Roles:")
        for rid, (name, desc) in ROLES.items():
            print(f"  {rid}: {name} - {desc}")
        print()
        print("Available Tests:")
        for name, desc in TESTS:
            print(f"  {name}: {desc}")
        return

    if os.geteuid() != 0:
        print("ERROR: This script must be run as root")
        sys.exit(1)

    if args.role > 0 and not check_daemon():
        print(f"ERROR: Daemon not running (socket not found: {SOCKET_PATH})")
        print("Start the daemon first: sudo ./target/release/bpfjailer-daemon")
        sys.exit(1)

    role_name, role_desc = ROLES.get(args.role, ("unknown", "Unknown role"))

    print("=" * 60)
    print("BpfJailer Security Test Suite")
    print("=" * 60)
    print(f"Role: {args.role} ({role_name})")
    print(f"Description: {role_desc}")
    print("=" * 60)
    print()

    # Filter tests if specific test requested
    tests_to_run = TESTS
    if args.test:
        tests_to_run = [(n, d) for n, d in TESTS if args.test.lower() in n.lower()]
        if not tests_to_run:
            print(f"No tests matching '{args.test}'")
            return

    for test_name, test_desc in tests_to_run:
        print(f"\n{'='*60}")
        print(f"TEST: {test_desc}")
        print(f"{'='*60}")
        sys.stdout.flush()

        run_test(test_name, args.role)

        print()

if __name__ == "__main__":
    main()
