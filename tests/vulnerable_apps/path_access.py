#!/usr/bin/env python3
"""
Sandbox Role Test

Tests the sandbox role which allows file access but blocks network and exec.
Similar to 'isolated' role - useful for sandboxed data processing.

Expected behavior:
- Role 0 (unenrolled): All operations allowed
- Role 9 (sandbox): File access allowed, network blocked, exec blocked
- Role 1 (restricted): All operations blocked
"""
import os
import sys
import socket
import subprocess

def test_sandbox():
    print("Sandbox Role Test")
    print("-" * 40)

    file_results = []
    net_result = None
    exec_result = None

    # Test 1: File access
    print("\n[File Access Tests]")

    os.makedirs("/tmp", exist_ok=True)

    # Write test
    try:
        with open("/tmp/sandbox_test.txt", 'w') as f:
            f.write("test")
        print("[+] Write /tmp/sandbox_test.txt: ALLOWED")
        file_results.append(True)
        os.unlink("/tmp/sandbox_test.txt")
    except PermissionError:
        print("[-] Write /tmp/sandbox_test.txt: BLOCKED")
        file_results.append(False)
    except Exception as e:
        print(f"[!] Write error: {e}")
        file_results.append(None)

    # Read /etc/passwd
    try:
        with open("/etc/passwd", 'r') as f:
            f.read(10)
        print("[+] Read /etc/passwd: ALLOWED")
        file_results.append(True)
    except PermissionError:
        print("[-] Read /etc/passwd: BLOCKED")
        file_results.append(False)
    except Exception as e:
        print(f"[!] Read /etc/passwd error: {e}")
        file_results.append(None)

    # Read /etc/shadow (should be BLOCKED by path rule)
    try:
        with open("/etc/shadow", 'r') as f:
            f.read(10)
        print("[+] Read /etc/shadow: ALLOWED")
        file_results.append(True)
    except PermissionError:
        print("[-] Read /etc/shadow: BLOCKED")
        file_results.append(False)
    except Exception as e:
        print(f"[!] Read /etc/shadow error: {e}")
        file_results.append(None)

    # Test 2: Network access (should be BLOCKED for sandbox)
    print("\n[Network Access Tests]")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("127.0.0.1", 80))
        sock.close()
        print("[+] TCP connect to 127.0.0.1:80: ALLOWED")
        net_result = True
    except PermissionError:
        print("[-] TCP connect to 127.0.0.1:80: BLOCKED (BpfJailer)")
        net_result = False
    except socket.timeout:
        print("[?] TCP connect: timeout (no listener)")
        net_result = None
    except ConnectionRefusedError:
        print("[+] TCP connect: refused (socket allowed, no listener)")
        net_result = True
    except Exception as e:
        print(f"[!] Network error: {type(e).__name__}: {e}")
        net_result = None

    # Test 3: Exec (should be BLOCKED for sandbox)
    print("\n[Exec Tests]")
    try:
        result = subprocess.run(["echo", "test"], capture_output=True, timeout=2)
        print("[+] Exec 'echo test': ALLOWED")
        exec_result = True
    except PermissionError:
        print("[-] Exec 'echo test': BLOCKED (BpfJailer)")
        exec_result = False
    except subprocess.TimeoutExpired:
        print("[?] Exec: timeout")
        exec_result = None
    except Exception as e:
        print(f"[-] Exec blocked: {type(e).__name__}")
        exec_result = False

    # Summary
    print("\n" + "=" * 40)

    # File OK if at least write and passwd read work
    file_ok = file_results[0] == True and file_results[1] == True
    net_blocked = net_result == False
    exec_blocked = exec_result == False

    print(f"File access: {'ALLOWED' if file_ok else 'BLOCKED'}")
    print(f"Network:     {'BLOCKED' if net_blocked else 'ALLOWED'}")
    print(f"Exec:        {'BLOCKED' if exec_blocked else 'ALLOWED'}")

    if file_ok and net_blocked and exec_blocked:
        print("\nSandbox role working correctly!")
    print("=" * 40)

    return file_results, net_result, exec_result

if __name__ == "__main__":
    test_sandbox()
