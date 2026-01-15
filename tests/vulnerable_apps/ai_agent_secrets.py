#!/usr/bin/env python3
"""
AI Agent Secrets Protection Tests - Tests for blocking access to sensitive files.

These tests verify that enrolled AI agents cannot:
1. Read SSH keys (~/.ssh/)
2. Read cloud credentials (~/.aws/, ~/.config/gcloud/, etc.)
3. Read process environment variables (/proc/*/environ)
4. Read system credential files (/etc/shadow, etc.)
5. Read other sensitive files (.git-credentials, .netrc, etc.)

Requires: Role with secrets protection file rules (e.g., ai_agent role)
"""

import os
import sys
import errno
import subprocess

EXPECTED_ROLE = "ai_agent"  # Role ID 12

# Sensitive file paths that should be blocked
# Format: (path_or_pattern, description, expand_home)
SENSITIVE_PATHS = [
    # SSH keys
    ("~/.ssh/id_rsa", "SSH private key", True),
    ("~/.ssh/id_ed25519", "SSH private key (ed25519)", True),
    ("~/.ssh/config", "SSH config", True),
    ("~/.ssh/known_hosts", "SSH known hosts", True),

    # Cloud credentials
    ("~/.aws/credentials", "AWS credentials", True),
    ("~/.aws/config", "AWS config", True),
    ("~/.config/gcloud/credentials.db", "GCloud credentials", True),
    ("~/.config/gcloud/application_default_credentials.json", "GCloud default creds", True),
    ("~/.azure/config", "Azure config", True),
    ("~/.kube/config", "Kubernetes config", True),

    # Docker config (may contain registry credentials)
    ("~/.docker/config.json", "Docker config", True),

    # System credentials
    ("/etc/shadow", "System shadow file", False),
    ("/etc/gshadow", "System gshadow file", False),

    # SSL/TLS private keys
    ("/etc/ssl/private/", "SSL private keys directory", False),

    # Package manager tokens
    ("~/.npmrc", "NPM config/token", True),
    ("~/.yarnrc", "Yarn config", True),
    ("~/.pypirc", "PyPI credentials", True),

    # Git credentials
    ("~/.git-credentials", "Git credentials", True),
    ("~/.netrc", "Netrc credentials", True),

    # GPG keys
    ("~/.gnupg/secring.gpg", "GPG secret keyring", True),
    ("~/.gnupg/private-keys-v1.d/", "GPG private keys", True),
]

# Process information paths that should be blocked
PROC_PATHS = [
    ("/proc/self/environ", "Self environment variables"),
    ("/proc/1/environ", "Init process environment"),
]

# Paths that should be ALLOWED (workspace/tmp)
ALLOWED_PATHS = [
    ("/tmp/test_file", "Temp file", False),
    ("~/.bashrc", "User bashrc (not sensitive)", True),
]


def test_file_access(path: str, description: str, expand_home: bool, should_block: bool) -> bool:
    """Test if a file can be accessed. Returns True if behavior matches expectation."""
    if expand_home:
        path = os.path.expanduser(path)

    try:
        with open(path, 'r') as f:
            content = f.read(100)  # Read just a bit

        if should_block:
            print(f"  ALLOWED (unexpected) - {description}: Read succeeded!")
            return False
        else:
            print(f"  ALLOWED - {description}: Read succeeded")
            return True

    except PermissionError as e:
        if should_block:
            print(f"  BLOCKED - {description}: Permission denied (BpfJailer)")
            return True
        else:
            print(f"  BLOCKED (unexpected) - {description}: {e}")
            return False

    except FileNotFoundError:
        # File doesn't exist - check if it would be blocked anyway
        # by trying to open for write
        print(f"  SKIPPED - {description}: File not found")
        return None

    except IsADirectoryError:
        # For directory paths, try to list contents
        try:
            os.listdir(path)
            if should_block:
                print(f"  ALLOWED (unexpected) - {description}: Directory listing succeeded")
                return False
            else:
                print(f"  ALLOWED - {description}: Directory accessible")
                return True
        except PermissionError:
            if should_block:
                print(f"  BLOCKED - {description}: Directory access denied")
                return True
            else:
                print(f"  BLOCKED (unexpected) - {description}")
                return False
        except FileNotFoundError:
            print(f"  SKIPPED - {description}: Directory not found")
            return None

    except Exception as e:
        print(f"  ERROR - {description}: {e}")
        return None


def test_sensitive_files():
    """Test that sensitive file paths are blocked."""
    print("\n=== Test: Sensitive Files Protection ===")
    print("Attempting to read sensitive files (should be blocked)...")

    results = []
    for path, desc, expand in SENSITIVE_PATHS:
        result = test_file_access(path, desc, expand, should_block=True)
        results.append(result)

    blocked = sum(1 for r in results if r is True)
    allowed = sum(1 for r in results if r is False)
    skipped = sum(1 for r in results if r is None)

    print(f"\n  Summary: Blocked={blocked}, Allowed={allowed}, Skipped={skipped}")
    return allowed == 0  # Pass if nothing sensitive was allowed


def test_proc_environ():
    """Test that /proc/*/environ is blocked."""
    print("\n=== Test: Process Environment Protection ===")
    print("Attempting to read /proc/*/environ (should be blocked)...")

    results = []
    for path, desc in PROC_PATHS:
        result = test_file_access(path, desc, expand_home=False, should_block=True)
        results.append(result)

    blocked = sum(1 for r in results if r is True)
    return blocked > 0  # At least some should be blocked


def test_allowed_paths():
    """Test that workspace/tmp paths are allowed."""
    print("\n=== Test: Allowed Paths ===")
    print("Attempting to access allowed paths (should succeed)...")

    # Create a test file in /tmp first
    test_file = "/tmp/bpfjailer_test_file"
    try:
        with open(test_file, 'w') as f:
            f.write("test content")
    except Exception as e:
        print(f"  BLOCKED (unexpected) - Cannot create temp file: {e}")
        return False

    results = []

    # Test reading the temp file
    result = test_file_access(test_file, "Temp test file", False, should_block=False)
    results.append(result)

    # Cleanup
    try:
        os.remove(test_file)
    except:
        pass

    allowed = sum(1 for r in results if r is True)
    return allowed > 0


def test_cat_sensitive():
    """Test that cat command on sensitive files is blocked."""
    print("\n=== Test: Cat Command Blocked ===")
    print("Testing cat on sensitive files...")

    blocked = 0
    for path, desc, expand in SENSITIVE_PATHS[:3]:  # Test first 3
        if expand:
            path = os.path.expanduser(path)

        if not os.path.exists(path):
            continue

        try:
            result = subprocess.run(
                ["cat", path],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                stderr = result.stderr.decode()
                if "Permission denied" in stderr:
                    print(f"  BLOCKED - cat {path}: Permission denied")
                    blocked += 1
                else:
                    print(f"  ERROR - cat {path}: {stderr.strip()}")
            else:
                print(f"  ALLOWED (unexpected) - cat {path}: Content read!")

        except Exception as e:
            print(f"  ERROR - {e}")

    if blocked == 0:
        print("  SKIPPED - No sensitive files found to test")
        return None

    return blocked > 0


def test_env_leak():
    """Test that environment variables cannot leak secrets."""
    print("\n=== Test: Environment Variable Protection ===")
    print("Checking for sensitive env var access prevention...")

    # Set a fake API key in environment
    os.environ["FAKE_API_KEY"] = "sk-test-secret-key-12345"
    os.environ["AWS_SECRET_KEY"] = "fake-aws-secret-key"

    # Try to read from /proc/self/environ
    try:
        with open("/proc/self/environ", "rb") as f:
            content = f.read()

        if b"FAKE_API_KEY" in content or b"AWS_SECRET_KEY" in content:
            print("  ALLOWED (unexpected) - /proc/self/environ readable with secrets!")
            return False
        else:
            print("  PARTIAL - /proc/self/environ readable but secrets not found")
            return None

    except PermissionError:
        print("  BLOCKED - /proc/self/environ access denied")
        return True
    except Exception as e:
        print(f"  ERROR - {e}")
        return None


def test_symlink_bypass():
    """Test that symlink attacks to sensitive files are blocked."""
    print("\n=== Test: Symlink Bypass Prevention ===")
    print("Testing symlink to sensitive file...")

    symlink_path = "/tmp/bpfjailer_test_symlink"

    # Clean up any existing symlink
    try:
        os.unlink(symlink_path)
    except:
        pass

    # Create symlink to a sensitive file
    target = os.path.expanduser("~/.ssh/id_rsa")
    if not os.path.exists(target):
        target = "/etc/shadow"

    try:
        os.symlink(target, symlink_path)
    except Exception as e:
        print(f"  SKIPPED - Cannot create symlink: {e}")
        return None

    try:
        with open(symlink_path, 'r') as f:
            content = f.read(100)
        print(f"  ALLOWED (unexpected) - Symlink bypass worked!")
        os.unlink(symlink_path)
        return False

    except PermissionError:
        print(f"  BLOCKED - Symlink to {target} denied")
        os.unlink(symlink_path)
        return True

    except FileNotFoundError:
        print(f"  SKIPPED - Target file not found")
        try:
            os.unlink(symlink_path)
        except:
            pass
        return None

    except Exception as e:
        print(f"  ERROR - {e}")
        try:
            os.unlink(symlink_path)
        except:
            pass
        return None


def main():
    print("=" * 60)
    print("AI Agent Secrets Protection Tests")
    print("=" * 60)
    print("Testing file access controls for sensitive data")
    print("These should block AI agents from reading secrets")

    results = {
        "sensitive_files": test_sensitive_files(),
        "proc_environ": test_proc_environ(),
        "allowed_paths": test_allowed_paths(),
        "cat_blocked": test_cat_sensitive(),
        "env_leak": test_env_leak(),
        "symlink_bypass": test_symlink_bypass(),
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
        print("\nWARNING: Some secrets protection is not working!")
        print("Ensure process is enrolled with ai_agent role.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
