#!/usr/bin/env python3
"""
Vulnerable App: Privilege Escalation Attempt

Simulates malware that tries various privilege escalation techniques:
1. Reading /etc/shadow
2. Writing to /etc/sudoers
3. Executing setuid binaries
4. Spawning shell processes

ATTACK: Malware tries to gain root access

MITIGATION:
- Role: restricted (ID 1) - Blocks file access, exec, network
- Role: isolated (ID 5) - Blocks network and exec
- All roles with allow_setuid: false
"""
import subprocess
import os
import sys

def try_read_shadow():
    """Attempt to read /etc/shadow (requires root)"""
    try:
        with open("/etc/shadow", 'r') as f:
            return f.read()[:100]
    except:
        return None

def try_write_sudoers():
    """Attempt to add user to sudoers"""
    try:
        with open("/etc/sudoers.d/backdoor", 'w') as f:
            f.write("ALL ALL=(ALL) NOPASSWD:ALL\n")
        return True
    except:
        return False

def try_exec_setuid():
    """Attempt to execute setuid binaries"""
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "id"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def try_spawn_shell():
    """Attempt to spawn a shell process"""
    try:
        result = subprocess.run(
            ["/bin/sh", "-c", "whoami"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0, result.stdout.decode().strip()
    except:
        return False, None

def main():
    print("=== Privilege Escalation Demo ===")
    print()

    # Test 1: Read shadow file
    print("Test 1: Read /etc/shadow (password hashes)")
    sys.stdout.flush()

    try:
        with open("/etc/shadow", 'r') as f:
            content = f.read()
        print(f"SUCCESS - Read shadow file ({len(content)} bytes) - CRITICAL!")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer or OS)")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Test 2: Write to sudoers
    print("Test 2: Write backdoor to /etc/sudoers.d/")
    sys.stdout.flush()

    try:
        with open("/etc/sudoers.d/test_backdoor", 'w') as f:
            f.write("# test\n")
        print("SUCCESS - Wrote to sudoers.d - CRITICAL!")
        os.remove("/etc/sudoers.d/test_backdoor")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer or OS)")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Test 3: Execute shell
    print("Test 3: Spawn shell process")
    sys.stdout.flush()

    try:
        result = subprocess.run(
            ["/bin/sh", "-c", "whoami"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"ALLOWED - Shell executed as: {result.stdout.strip()}")
        else:
            print(f"BLOCKED - Shell execution failed")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked exec)")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Test 4: Fork bomb prevention (just test fork capability)
    print("Test 4: Process creation capability")
    sys.stdout.flush()

    try:
        pid = os.fork()
        if pid == 0:
            # Child
            os._exit(0)
        else:
            os.waitpid(pid, 0)
            print("ALLOWED - Process creation permitted")
    except PermissionError:
        print("BLOCKED - Permission denied")
    except Exception as e:
        print(f"ERROR - {e}")

if __name__ == "__main__":
    main()
