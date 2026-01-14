# BpfJailer Security Test Suite

This directory contains vulnerable Python applications that demonstrate common security vulnerabilities and how BpfJailer policies can mitigate them.

## Quick Start

```bash
# Install test dependencies (optional, for xattr tests)
pip3 install -r tests/requirements.txt

# Start the BpfJailer daemon
cd /root/bpfjailer
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
| 9 | sandbox | Allowed | Blocked | Blocked | Sandboxed data processing |
| 10 | wildcard_test | Path rules | Blocked | Blocked | Testing wildcard paths |
| 11 | tee_protected | Allowed | Allowed | Allowed | TEE: blocks ptrace/modules/BPF |

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

---

### 8. Sandbox Role Test (`path_access.py`)

**Purpose**: Tests the sandbox role which allows file access but blocks network and exec.

**Use Case**: Sandboxed data processing tasks that need file I/O but no network or shell access.

**Mitigated By**:
| Role | File | Network | Exec |
|------|------|---------|------|
| sandbox | Allowed | Blocked | Blocked |
| isolated | Allowed | Blocked | Blocked |
| restricted | Blocked | Blocked | Blocked |

```bash
# Without jailing - all operations allowed
sudo python3 tests/vulnerable_apps/path_access.py

# With sandbox role - file allowed, network/exec blocked
sudo python3 tests/vulnerable_apps/run_tests.py --role 9 --test path_access
```

**Expected Output with Sandbox Role**:
```
File access: ALLOWED
Network:     BLOCKED
Exec:        BLOCKED
Sandbox role working correctly!
```

---

### 9. Wildcard Path Matching (`wildcard_access.py`)

**Purpose**: Tests BpfJailer's wildcard path matching capabilities for fine-grained file access control.

**Tests**:
- Directory wildcards: `/tmp/allowed/` allows all files under the directory
- Single component wildcards: `/tmp/mixed/*/data.txt` matches any user's data.txt
- Specific path blocking: `/tmp/blocked/` denies access to entire directory
- Override rules: More specific rules override general wildcards

**Wildcard Patterns**:
| Pattern | Description |
|---------|-------------|
| `/path/to/dir/` | Allows all files under directory |
| `/path/*/file.txt` | Matches single directory component |
| `/path/to/file` | Matches exact file |

```bash
# Run wildcard test with dedicated role
sudo python3 tests/vulnerable_apps/run_tests.py --role 10 --test wildcard_access
```

**Expected Output**:
```
Directory allow (/tmp/allowed/): PASS
Directory block (/tmp/blocked/): PASS
Wildcard match (*/data.txt):     PASS
Wildcard block (/secret/):       PASS
```

---

### 10. Auto-Enrollment Methods (`auto_enrollment.py`)

**Purpose**: Tests the alternative enrollment infrastructure for automatic process enrollment.

**Methods Tested**:
| Method | Description |
|--------|-------------|
| Executable | Auto-enroll by binary inode at exec time |
| Cgroup | Auto-enroll by cgroup membership |
| Xattr | Enrollment markers via extended attributes |

```bash
# Run auto-enrollment infrastructure test
sudo python3 tests/vulnerable_apps/auto_enrollment.py

# Test with daemon running
sudo python3 tests/vulnerable_apps/run_tests.py --test auto_enrollment
```

**Expected Output**:
```
Executable enrollment infrastructure: PASS
Cgroup enrollment infrastructure:     PASS
Xattr enrollment markers:             PASS (or SKIP if xattr module missing)
```

**Policy Configuration for Auto-Enrollment**:
```json
{
  "exec_enrollments": [
    {"executable_path": "/usr/bin/nginx", "pod_id": 1000, "role": "webserver"}
  ],
  "cgroup_enrollments": [
    {"cgroup_path": "/sys/fs/cgroup/myapp", "pod_id": 2000, "role": "sandbox"}
  ]
}
```

---

### 11. TEE Protection (`tee_protection.py`)

**Purpose**: Tests security restrictions for Trusted Execution Environment (TEE) scenarios.

**Protections Tested**:
| Protection | Flag | Description |
|------------|------|-------------|
| Ptrace Blocking | `allow_ptrace: false` | Prevents debugging/memory inspection |
| Module Loading | `allow_module_load: false` | Prevents kernel module loading |
| BPF Operations | `allow_bpf_load: false` | Prevents BPF program loading |

```bash
# Run TEE protection tests
sudo python3 tests/vulnerable_apps/tee_protection.py

# Test with tee_protected role (ID 11)
sudo python3 tests/vulnerable_apps/run_tests.py --role 11 --test tee_protection
```

**Expected Output (when enrolled with tee_protected role)**:
```
ptrace_self:   BLOCKED
ptrace_child:  BLOCKED
strace:        BLOCKED
module_load:   BLOCKED
insmod:        BLOCKED
bpf_syscall:   BLOCKED
bpftool:       BLOCKED
```

**Policy Configuration for TEE Protection**:
```json
{
  "tee_protected": {
    "id": 11,
    "flags": {
      "allow_file_access": true,
      "allow_network": true,
      "allow_exec": true,
      "allow_ptrace": false,
      "allow_module_load": false,
      "allow_bpf_load": false
    },
    "file_paths": [
      {"pattern": "/proc/", "allow": false},
      {"pattern": "/sys/kernel/", "allow": false}
    ]
  }
}
```

---

## Mitigation Summary Matrix

| Vulnerability | restricted | webserver | isolated | sandbox | wildcard_test | permissive |
|--------------|------------|-----------|----------|---------|---------------|------------|
| Path Traversal | BLOCKED | Partial | Partial | BLOCKED | Controlled | Allowed |
| Command Injection | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED | Allowed |
| Reverse Shell | BLOCKED | Partial | BLOCKED | BLOCKED | BLOCKED | Allowed |
| SSRF | BLOCKED | Partial | BLOCKED | BLOCKED | BLOCKED | Allowed |
| Arbitrary Write | BLOCKED | Partial | Partial | Partial | Controlled | Allowed |
| Crypto Miner | BLOCKED | BLOCKED | Partial | BLOCKED | BLOCKED | Allowed |
| Privilege Escalation | BLOCKED | Partial | BLOCKED | BLOCKED | BLOCKED | Allowed |
| Path Access | BLOCKED | Partial | Partial | Controlled | Controlled | Allowed |
| Wildcard Paths | BLOCKED | Partial | Partial | N/A | Controlled | Allowed |

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

### Use `sandbox` (ID 9) when:
- Processing files without network access
- Running data transformation tasks
- Same as `isolated` - allows file, blocks network/exec

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
