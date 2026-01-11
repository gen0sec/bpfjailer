#!/usr/bin/env python3
"""
Vulnerable App: Crypto Miner / Resource Abuse

Simulates malware that:
1. Downloads a crypto miner binary
2. Executes it to mine cryptocurrency
3. Connects to mining pool

ATTACK: Malware uses compute resources for unauthorized mining

MITIGATION:
- Role: restricted (ID 1) - Blocks exec, network, file access
- Role: isolated (ID 5) - Blocks network (can't reach mining pool)
- Role: webserver (ID 3) - Blocks exec (can't run miner binary)
"""
import subprocess
import socket
import sys
import os

def download_miner():
    """Simulates downloading a miner binary"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        # Try to connect to simulate download
        result = sock.connect_ex(("127.0.0.1", 80))
        sock.close()
        return result in [0, 111]  # 0 = connected, 111 = refused but allowed
    except:
        return False

def execute_miner():
    """Simulates executing the miner binary"""
    try:
        result = subprocess.run(
            ["/bin/echo", "Mining..."],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def connect_mining_pool():
    """Simulates connecting to a mining pool"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        # Common mining pool port
        result = sock.connect_ex(("127.0.0.1", 3333))
        sock.close()
        return result in [0, 111]
    except:
        return False

def main():
    print("=== Crypto Miner / Resource Abuse Demo ===")
    print()

    # Phase 1: Download miner
    print("Phase 1: Download miner binary from C2 server")
    sys.stdout.flush()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 80))
        sock.close()

        if result == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked download)")
        elif result in [0, 111]:
            print("ALLOWED - Network download permitted")
        else:
            print(f"RESULT - Connect returned: {result}")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked download)")
    except OSError as e:
        if "Permission denied" in str(e):
            print("BLOCKED - Permission denied (BpfJailer blocked download)")
        else:
            print(f"ALLOWED - Network accessible (error: {e})")

    print()

    # Phase 2: Execute miner
    print("Phase 2: Execute miner binary")
    sys.stdout.flush()

    try:
        result = subprocess.run(
            ["/bin/true"],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            print("ALLOWED - Binary execution permitted")
        else:
            print("BLOCKED - Execution failed")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked exec)")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Phase 3: Connect to mining pool
    print("Phase 3: Connect to mining pool (port 3333)")
    sys.stdout.flush()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 3333))
        sock.close()

        if result == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked pool connection)")
        elif result in [0, 111]:
            print("ALLOWED - Mining pool connection permitted")
        else:
            print(f"RESULT - Connect returned: {result}")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked pool connection)")
    except OSError as e:
        if "Permission denied" in str(e):
            print("BLOCKED - Permission denied (BpfJailer blocked pool connection)")
        else:
            print(f"ALLOWED - Network accessible (error: {e})")

    print()
    print("Summary: Miner needs network + exec. Block either to prevent mining.")

if __name__ == "__main__":
    main()
