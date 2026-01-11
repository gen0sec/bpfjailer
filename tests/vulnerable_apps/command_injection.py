#!/usr/bin/env python3
"""
Vulnerable App: Command Injection

Simulates a web app that executes shell commands with user input.
An attacker could execute arbitrary commands on the system.

ATTACK: Input "google.com; cat /etc/shadow"

MITIGATION:
- Role: restricted (ID 1) - Blocks exec and file access
- Role: webserver (ID 3) - Blocks exec (allow_exec: false)
- Role: isolated (ID 5) - Blocks network and exec
"""
import subprocess
import sys
import os

def ping_host(user_input):
    """Vulnerable: directly interpolates user input into shell command"""
    # NO SANITIZATION - vulnerable to command injection!
    # Attacker input: "google.com; cat /etc/shadow"

    cmd = f"ping -c 1 {user_input}"
    return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

def main():
    print("=== Command Injection Vulnerability Demo ===")
    print()

    # Simulate attack - injecting command to read shadow file
    malicious_input = "127.0.0.1; cat /etc/shadow"
    print(f"Attacker input: {malicious_input}")
    print(f"Resulting command: ping -c 1 {malicious_input}")
    print()

    print("Attempting command injection...")
    sys.stdout.flush()

    try:
        # Try to execute a command (simpler version for demo)
        result = subprocess.run(
            ["/bin/cat", "/etc/passwd"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"SUCCESS - Command executed, output ({len(result.stdout)} bytes):")
            print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        else:
            print(f"BLOCKED - Command failed: {result.stderr}")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked exec)")
    except FileNotFoundError:
        print("BLOCKED - Binary not found or execution blocked")
    except Exception as e:
        print(f"ERROR - {e}")

if __name__ == "__main__":
    main()
