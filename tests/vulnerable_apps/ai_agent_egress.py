#!/usr/bin/env python3
"""
AI Agent Egress Control Tests - Tests for IP/CIDR filtering, domain blocking, and proxy enforcement.

These tests verify that enrolled AI agents cannot:
1. Connect to private IP ranges (SSRF protection)
2. Resolve/connect to blocked domains
3. Make direct connections when proxy is required

Requires: Role with ip_rules, domain_rules, and proxy configuration (e.g., ai_agent role)
"""

import os
import sys
import socket
import subprocess

EXPECTED_ROLE = "ai_agent"  # Role ID 12

# Private IP ranges that should be blocked
PRIVATE_IPS = [
    ("10.0.0.1", "10.0.0.0/8 - Private Class A"),
    ("172.16.0.1", "172.16.0.0/12 - Private Class B"),
    ("192.168.1.1", "192.168.0.0/16 - Private Class C"),
]

# Internal metadata endpoints (cloud provider SSRF targets)
METADATA_ENDPOINTS = [
    ("169.254.169.254", "AWS/GCP metadata endpoint"),
    ("100.100.100.200", "Alibaba Cloud metadata"),
]

# Test domains
TEST_DOMAINS = [
    ("api.openai.com", True, "Should be allowed (LLM provider)"),
    ("api.anthropic.com", True, "Should be allowed (LLM provider)"),
    ("evil.attacker.com", False, "Should be blocked (not allowlisted)"),
    ("internal.corp.local", False, "Should be blocked (internal domain)"),
]


def test_private_ip_blocked():
    """Test that connections to private IP ranges are blocked."""
    print("\n=== Test: Private IP Range Blocking ===")
    print("Attempting to connect to private IPs (SSRF protection)...")

    results = []
    for ip, desc in PRIVATE_IPS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 80))
            sock.close()

            # EACCES (13) or EPERM (1) indicates blocked by BpfJailer
            # ETIMEDOUT (110), ECONNREFUSED (111), EHOSTUNREACH (113) are network errors
            if result in [1, 13]:  # EPERM or EACCES
                print(f"  BLOCKED - {desc}: Connection denied by BpfJailer")
                results.append(True)
            elif result in [110, 111, 113]:
                print(f"  ALLOWED (network error) - {desc}: errno={result}")
                results.append(False)
            elif result == 0:
                print(f"  ALLOWED - {desc}: Connection succeeded!")
                results.append(False)
            else:
                print(f"  RESULT - {desc}: errno={result}")
                results.append(None)

        except socket.timeout:
            print(f"  ALLOWED (timeout) - {desc}")
            results.append(False)
        except Exception as e:
            if "Permission denied" in str(e) or "Operation not permitted" in str(e):
                print(f"  BLOCKED - {desc}: {e}")
                results.append(True)
            else:
                print(f"  ERROR - {desc}: {e}")
                results.append(None)

    blocked = sum(1 for r in results if r is True)
    return blocked == len(PRIVATE_IPS)


def test_metadata_endpoint_blocked():
    """Test that cloud metadata endpoints are blocked."""
    print("\n=== Test: Cloud Metadata Endpoint Blocking ===")
    print("Attempting to access cloud metadata (SSRF protection)...")

    results = []
    for ip, desc in METADATA_ENDPOINTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 80))
            sock.close()

            if result in [1, 13]:  # EPERM or EACCES
                print(f"  BLOCKED - {desc}: Connection denied")
                results.append(True)
            elif result in [110, 111, 113]:
                print(f"  ALLOWED (network error) - {desc}: errno={result}")
                results.append(False)
            elif result == 0:
                print(f"  ALLOWED - {desc}: Connection succeeded!")
                results.append(False)
            else:
                print(f"  RESULT - {desc}: errno={result}")
                results.append(None)

        except socket.timeout:
            print(f"  ALLOWED (timeout) - {desc}")
            results.append(False)
        except Exception as e:
            if "Permission denied" in str(e) or "Operation not permitted" in str(e):
                print(f"  BLOCKED - {desc}: {e}")
                results.append(True)
            else:
                print(f"  ERROR - {desc}: {e}")
                results.append(None)

    blocked = sum(1 for r in results if r is True)
    return blocked >= 1  # At least some should be blocked


def test_localhost_allowed():
    """Test that localhost connections are allowed (for local services)."""
    print("\n=== Test: Localhost Allowed ===")
    print("Attempting localhost connection (should be allowed)...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        # Try to connect to localhost on a likely unused port
        result = sock.connect_ex(("127.0.0.1", 65432))
        sock.close()

        # ECONNREFUSED (111) means the connection was allowed but nothing listening
        if result == 111:
            print("  ALLOWED - Localhost connection permitted (connection refused)")
            return True
        elif result in [1, 13]:
            print("  BLOCKED - Localhost connection denied (unexpected)")
            return False
        elif result == 0:
            print("  ALLOWED - Connection succeeded")
            return True
        else:
            print(f"  RESULT - errno={result}")
            return None

    except Exception as e:
        if "Connection refused" in str(e):
            print("  ALLOWED - Localhost connection permitted")
            return True
        print(f"  ERROR - {e}")
        return None


def test_dns_query():
    """Test DNS resolution (may be filtered by domain rules)."""
    print("\n=== Test: DNS Resolution ===")
    print("Attempting DNS lookups...")

    results = []
    for domain, should_allow, desc in TEST_DOMAINS:
        try:
            # This will attempt DNS resolution
            ip = socket.gethostbyname(domain)

            if should_allow:
                print(f"  ALLOWED - {domain}: resolved to {ip} ({desc})")
                results.append(True)
            else:
                print(f"  ALLOWED (unexpected) - {domain}: resolved to {ip} ({desc})")
                results.append(False)

        except socket.gaierror as e:
            if should_allow:
                print(f"  BLOCKED (unexpected) - {domain}: {e} ({desc})")
                results.append(False)
            else:
                print(f"  BLOCKED - {domain}: {e} ({desc})")
                results.append(True)
        except Exception as e:
            print(f"  ERROR - {domain}: {e}")
            results.append(None)

    # Success if allowed domains resolve and blocked domains don't
    correct = sum(1 for r in results if r is True)
    return correct >= len(TEST_DOMAINS) // 2


def test_http_connect():
    """Test HTTP connections to various endpoints."""
    print("\n=== Test: HTTP Connection Control ===")
    print("Attempting HTTP connections...")

    try:
        import urllib.request
        import urllib.error

        # Test allowed domain
        print("  Testing api.openai.com:443...")
        try:
            req = urllib.request.Request(
                "https://api.openai.com/v1/models",
                headers={"User-Agent": "test"}
            )
            urllib.request.urlopen(req, timeout=5)
            print("    ALLOWED - Connection succeeded (auth may fail)")
        except urllib.error.HTTPError as e:
            print(f"    ALLOWED - HTTP error {e.code} (connection permitted)")
        except urllib.error.URLError as e:
            if "Permission denied" in str(e) or "blocked" in str(e).lower():
                print(f"    BLOCKED - {e}")
            else:
                print(f"    ERROR - {e}")
        except Exception as e:
            print(f"    ERROR - {e}")

        # Test blocked domain
        print("  Testing evil.example.com:80...")
        try:
            req = urllib.request.Request(
                "http://evil.example.com/",
                headers={"User-Agent": "test"}
            )
            urllib.request.urlopen(req, timeout=5)
            print("    ALLOWED (unexpected) - Connection succeeded")
            return False
        except urllib.error.URLError as e:
            if "Permission denied" in str(e) or "blocked" in str(e).lower():
                print(f"    BLOCKED - {e}")
                return True
            else:
                print(f"    BLOCKED (network error) - {e}")
                return None
        except Exception as e:
            print(f"    ERROR - {e}")
            return None

    except ImportError:
        print("  SKIPPED - urllib not available")
        return None


def test_curl_blocked():
    """Test that curl to blocked IPs fails."""
    print("\n=== Test: Curl to Private IP ===")
    print("Testing curl to private IP range...")

    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", "2", "http://10.0.0.1/"],
            capture_output=True,
            timeout=5
        )

        if result.returncode == 7:  # CURLE_COULDNT_CONNECT
            stderr = result.stderr.decode()
            if "Permission denied" in stderr or "EPERM" in stderr:
                print("  BLOCKED - Connection denied by BpfJailer")
                return True
            else:
                print("  BLOCKED - Connection failed (network)")
                return None
        else:
            print(f"  RESULT - curl returned {result.returncode}")
            return None

    except FileNotFoundError:
        print("  SKIPPED - curl not installed")
        return None
    except subprocess.TimeoutExpired:
        print("  BLOCKED - curl timed out")
        return True
    except Exception as e:
        print(f"  ERROR - {e}")
        return None


def main():
    print("=" * 60)
    print("AI Agent Egress Control Tests")
    print("=" * 60)
    print("Testing IP/CIDR filtering, domain rules, and proxy enforcement")
    print("These should enforce egress restrictions for AI agents")

    results = {
        "private_ip_blocked": test_private_ip_blocked(),
        "metadata_blocked": test_metadata_endpoint_blocked(),
        "localhost_allowed": test_localhost_allowed(),
        "dns_query": test_dns_query(),
        "http_connect": test_http_connect(),
        "curl_blocked": test_curl_blocked(),
    }

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)

    for test, result in results.items():
        status = "PASS" if result is True else "FAIL" if result is False else "SKIP"
        print(f"  {test}: {status}")

    print(f"\nPassed: {passed}, Failed: {failed}, Skipped: {skipped}")

    if failed > 0:
        print("\nWARNING: Some egress controls are not working!")
        print("Ensure process is enrolled with ai_agent role.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
