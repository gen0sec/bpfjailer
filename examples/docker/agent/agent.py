#!/usr/bin/env python3
"""
Example AI Agent - Demonstrates BpfJailer security controls

This agent simulates common AI agent behaviors and shows how BpfJailer
protects against various attack vectors:

1. Egress control - Only allowed to contact LLM API endpoints
2. Secrets protection - Cannot read SSH keys, AWS credentials, etc.
3. Command injection - Cannot execute arbitrary commands
4. SSRF protection - Cannot access internal network resources
"""

import os
import sys
import time
import socket
import json

ENROLLMENT_SOCKET = "/run/bpfjailer/enrollment.sock"
AI_AGENT_ROLE_ID = 12
AI_AGENT_POD_ID = 1000

def log(msg):
    """Print timestamped log message."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def enroll_with_bpfjailer():
    """Enroll this process with BpfJailer daemon."""
    log("Enrolling with BpfJailer...")

    if not os.path.exists(ENROLLMENT_SOCKET):
        log(f"  Socket not found: {ENROLLMENT_SOCKET}")
        return False

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(ENROLLMENT_SOCKET)

        request = {"Enroll": {"pod_id": AI_AGENT_POD_ID, "role_id": AI_AGENT_ROLE_ID}}
        sock.send((json.dumps(request) + "\n").encode())

        response = sock.recv(4096).decode().strip()
        sock.close()

        if "Success" in response:
            log(f"  Enrolled with role {AI_AGENT_ROLE_ID}")
            # Trigger enrollment migration
            try:
                open("/dev/null", "r").close()
            except:
                pass
            return True
        else:
            log(f"  Failed: {response}")
            return False
    except Exception as e:
        log(f"  Error: {e}")
        return False

def test_llm_api_access():
    """Test if we can reach LLM API endpoints (should be allowed)."""
    log("Testing LLM API access...")

    allowed_hosts = [
        ("api.openai.com", 443),
        ("api.anthropic.com", 443),
    ]

    for host, port in allowed_hosts:
        try:
            # Resolve hostname
            ip = socket.gethostbyname(host)
            log(f"  {host} resolved to {ip}")

            # Try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                log(f"  [OK] {host}:{port} - Connection successful")
            else:
                log(f"  [WARN] {host}:{port} - Connection failed (errno={result})")

        except socket.gaierror as e:
            log(f"  [BLOCKED] {host} - DNS resolution blocked: {e}")
        except Exception as e:
            log(f"  [ERROR] {host} - {e}")

def test_internal_network_blocked():
    """Test if internal network access is blocked (SSRF protection)."""
    log("Testing internal network blocking (SSRF protection)...")

    blocked_targets = [
        ("10.0.0.1", 80, "Private network 10.0.0.0/8"),
        ("172.16.0.1", 80, "Private network 172.16.0.0/12"),
        ("192.168.1.1", 80, "Private network 192.168.0.0/16"),
        ("169.254.169.254", 80, "AWS/GCP metadata endpoint"),
    ]

    for ip, port, desc in blocked_targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result in [1, 13]:  # EPERM or EACCES
                log(f"  [BLOCKED] {ip}:{port} - {desc}")
            elif result in [110, 111, 113]:
                log(f"  [ALLOWED] {ip}:{port} - Network error ({desc})")
            else:
                log(f"  [RESULT] {ip}:{port} - errno={result} ({desc})")

        except socket.timeout:
            log(f"  [ALLOWED?] {ip}:{port} - Timeout ({desc})")
        except Exception as e:
            if "Permission denied" in str(e):
                log(f"  [BLOCKED] {ip}:{port} - {desc}")
            else:
                log(f"  [ERROR] {ip}:{port} - {e}")

def test_secrets_protection():
    """Test if secrets are protected from reading."""
    log("Testing secrets protection...")

    secret_paths = [
        "/root/.ssh/id_rsa",
        "/root/.aws/credentials",
        "/etc/shadow",
        "/proc/self/environ",
    ]

    for path in secret_paths:
        try:
            with open(path, 'r') as f:
                content = f.read(10)
            log(f"  [ALLOWED!] {path} - Content readable (security issue!)")
        except PermissionError:
            log(f"  [BLOCKED] {path} - Permission denied (protected)")
        except FileNotFoundError:
            log(f"  [SKIP] {path} - File not found")
        except Exception as e:
            log(f"  [ERROR] {path} - {e}")

def test_command_execution():
    """Test if command execution is blocked."""
    log("Testing command execution blocking...")

    import subprocess

    commands = [
        ["id"],
        ["whoami"],
        ["cat", "/etc/passwd"],
    ]

    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            log(f"  [ALLOWED] {' '.join(cmd)} - Executed (exit={result.returncode})")
        except PermissionError:
            log(f"  [BLOCKED] {' '.join(cmd)} - Permission denied")
        except FileNotFoundError:
            log(f"  [SKIP] {' '.join(cmd)} - Command not found")
        except Exception as e:
            log(f"  [ERROR] {' '.join(cmd)} - {e}")

def simulate_ai_agent():
    """Simulate AI agent behavior."""
    log("Simulating AI agent task...")

    # Read task from environment or use default
    task = os.environ.get("AGENT_TASK", "Analyze code in /app directory")
    log(f"  Task: {task}")

    # Simulate reading workspace files (should be allowed)
    workspace = "/app"
    if os.path.exists(workspace):
        files = os.listdir(workspace)
        log(f"  Workspace files: {files}")

    # Simulate writing to temp (should be allowed)
    try:
        with open("/tmp/agent_output.txt", "w") as f:
            f.write("Agent output: Task completed successfully\n")
        log("  [OK] Wrote output to /tmp/agent_output.txt")
    except Exception as e:
        log(f"  [ERROR] Cannot write output: {e}")

    # Simulate API call (should be allowed to LLM endpoints only)
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        log("  API key present, would make LLM API call...")
    else:
        log("  No API key, skipping LLM API call")

def main():
    log("=" * 50)
    log("BpfJailer AI Agent Security Demo")
    log("=" * 50)
    log("")

    # Enroll with BpfJailer first
    enroll_with_bpfjailer()
    log("")

    # Run security tests
    test_llm_api_access()
    log("")

    test_internal_network_blocked()
    log("")

    test_secrets_protection()
    log("")

    test_command_execution()
    log("")

    # Simulate agent work
    simulate_ai_agent()
    log("")

    log("=" * 50)
    log("Demo complete")
    log("=" * 50)

    # Keep container running for inspection
    log("Container will stay running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log("Shutting down...")

if __name__ == "__main__":
    main()
