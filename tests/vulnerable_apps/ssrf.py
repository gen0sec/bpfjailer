#!/usr/bin/env python3
"""
Vulnerable App: Server-Side Request Forgery (SSRF)

Simulates a web app that fetches URLs based on user input.
An attacker could access internal services or cloud metadata endpoints.

ATTACK: curl "http://localhost:8000/fetch?url=http://169.254.169.254/latest/meta-data/"

MITIGATION:
- Role: restricted (ID 1) - Blocks all network
- Role: isolated (ID 5) - Blocks all network
- Role: webserver (ID 3) - Only allows ports 80, 443 (blocks metadata port 80 on 169.254.x.x)
- Custom role with network_rules blocking specific IPs (future feature)
"""
import socket
import sys
import os

def fetch_url_vulnerable(user_url):
    """Vulnerable: directly uses user-provided URL without validation"""
    # NO VALIDATION - vulnerable to SSRF!
    # Attacker input: "http://169.254.169.254/latest/meta-data/"
    # or "http://internal-service:8080/admin"

    import urllib.request
    try:
        response = urllib.request.urlopen(user_url, timeout=5)
        return response.read()
    except Exception as e:
        return f"Error: {e}"

def main():
    print("=== SSRF (Server-Side Request Forgery) Demo ===")
    print()

    # Test 1: Access cloud metadata endpoint
    print("Test 1: SSRF to cloud metadata (169.254.169.254:80)")
    print("In AWS/GCP, this exposes instance credentials!")
    sys.stdout.flush()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("169.254.169.254", 80))
        sock.close()

        if result == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        elif result == 0:
            print("ALLOWED - Connected to metadata endpoint")
        elif result == 111:
            print("ALLOWED - Connection permitted (no metadata service)")
        else:
            print(f"RESULT - Connect returned: {result}")
    except PermissionError:
        print("BLOCKED - Permission denied (BpfJailer blocked connect)")
    except OSError as e:
        if "Permission denied" in str(e) or e.errno == 13:
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        elif "Network is unreachable" in str(e):
            print("ALLOWED - Network permitted (route unavailable)")
        else:
            print(f"NETWORK ERROR - {e}")
    except Exception as e:
        print(f"ERROR - {e}")

    print()

    # Test 2: Access internal service
    print("Test 2: SSRF to internal service (127.0.0.1:6379 - Redis)")
    sys.stdout.flush()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 6379))
        sock.close()

        if result == 13:  # EACCES
            print("BLOCKED - Permission denied (BpfJailer blocked connect)")
        elif result == 0:
            print("ALLOWED - Connected to internal Redis")
        elif result == 111:
            print("ALLOWED - Connection permitted (Redis not running)")
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
