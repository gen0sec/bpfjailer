#!/usr/bin/env python3
"""
Vulnerable App: Path Traversal / Arbitrary File Read

Simulates a web app that reads files based on user input without sanitization.
An attacker could read /etc/shadow, /etc/passwd, or other sensitive files.

ATTACK: curl "http://localhost:8000/read?file=../../../etc/passwd"

MITIGATION:
- Role: restricted (ID 1) - Blocks all file access
- Role: webserver (ID 3) - Could be extended with file_paths patterns
"""
import os
import sys

def read_user_file(user_input):
    """Vulnerable: directly uses user input in file path"""
    base_dir = "/var/www/data"
    file_path = os.path.join(base_dir, user_input)

    # NO SANITIZATION - vulnerable to path traversal!
    # Attacker input: "../../../etc/passwd"

    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"

def main():
    print("=== Path Traversal Vulnerability Demo ===")
    print()

    # Simulate attack - reading /etc/passwd via path traversal
    malicious_input = "../../../etc/passwd"
    print(f"Attacker input: {malicious_input}")
    print(f"Resolved path: {os.path.normpath(os.path.join('/var/www/data', malicious_input))}")
    print()

    print("Attempting to read /etc/passwd via path traversal...")
    sys.stdout.flush()

    try:
        with open("/etc/passwd", 'r') as f:
            content = f.read()
            print(f"SUCCESS - File read ({len(content)} bytes):")
            print(content[:200] + "..." if len(content) > 200 else content)
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked file access)")
    except Exception as e:
        print(f"ERROR - {e}")

if __name__ == "__main__":
    main()
