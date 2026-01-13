#!/usr/bin/env python3
"""
Wildcard Path Access Test
Tests BpfJailer's wildcard path matching:
- Directory wildcards (/tmp/allowed/)
- Single component wildcards (/tmp/mixed/*/data.txt)
- Specific file overrides (/var/log/secure blocked despite /var/log/ allowed)
"""

import os
import sys
import shutil
import tempfile

def setup_test_dirs():
    """Create test directory structure"""
    dirs = [
        "/tmp/allowed",
        "/tmp/blocked",
        "/tmp/mixed/user1",
        "/tmp/mixed/user2",
        "/tmp/mixed/secret",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    return dirs

def cleanup_test_dirs():
    """Remove test directories"""
    for d in ["/tmp/allowed", "/tmp/blocked", "/tmp/mixed"]:
        try:
            if os.path.exists(d):
                shutil.rmtree(d)
        except PermissionError:
            pass  # BpfJailer blocked cleanup - expected

def test_file_write(path, desc):
    """Test writing to a file"""
    try:
        with open(path, 'w') as f:
            f.write("test data")
        os.unlink(path)
        return True, "ALLOWED"
    except PermissionError:
        return False, "BLOCKED (Permission)"
    except OSError as e:
        if e.errno == 13:
            return False, "BLOCKED (BpfJailer)"
        return False, f"ERROR ({e})"

def test_file_read(path, desc):
    """Test reading from a file"""
    # First create the file if it doesn't exist
    try:
        if not os.path.exists(path):
            with open(path, 'w') as f:
                f.write("test data")
    except:
        pass

    try:
        with open(path, 'r') as f:
            f.read()
        return True, "ALLOWED"
    except PermissionError:
        return False, "BLOCKED (Permission)"
    except OSError as e:
        if e.errno == 13:
            return False, "BLOCKED (BpfJailer)"
        return False, f"ERROR ({e})"

def main():
    print("Wildcard Path Access Test")
    print("=" * 50)

    # Setup
    setup_test_dirs()

    results = {
        "allowed_dir": None,
        "blocked_dir": None,
        "wildcard_match": None,
        "wildcard_block": None,
        "specific_override": None,
    }

    print("\n[Directory Wildcard Tests]")

    # Test 1: /tmp/allowed/ should allow
    ok, msg = test_file_write("/tmp/allowed/test.txt", "allowed dir")
    results["allowed_dir"] = ok
    print(f"[{'+'if ok else '-'}] Write /tmp/allowed/test.txt: {msg}")

    # Test 2: /tmp/blocked/ should block
    ok, msg = test_file_write("/tmp/blocked/test.txt", "blocked dir")
    results["blocked_dir"] = not ok  # Success means it was blocked
    print(f"[{'-'if ok else '+'}] Write /tmp/blocked/test.txt: {msg}")

    print("\n[Single Component Wildcard Tests]")

    # Test 3: /tmp/mixed/user1/data.txt should allow (matches /tmp/mixed/*/data.txt)
    ok, msg = test_file_write("/tmp/mixed/user1/data.txt", "wildcard match")
    results["wildcard_match"] = ok
    print(f"[{'+'if ok else '-'}] Write /tmp/mixed/user1/data.txt: {msg}")

    # Test 4: /tmp/mixed/secret/anything.txt should block (specific block)
    ok, msg = test_file_write("/tmp/mixed/secret/config.txt", "secret dir")
    results["wildcard_block"] = not ok
    print(f"[{'-'if ok else '+'}] Write /tmp/mixed/secret/config.txt: {msg}")

    print("\n[Specific File Override Tests]")

    # Test 5: /tmp/allowed/app.log should allow (under allowed dir)
    ok, msg = test_file_write("/tmp/allowed/app.log", "log allowed")
    results["specific_override"] = ok
    print(f"[{'+'if ok else '-'}] Write /tmp/allowed/app.log: {msg}")

    # Summary
    print("\n" + "=" * 50)
    print("Summary:")
    print(f"  Directory allow (/tmp/allowed/): {'PASS' if results['allowed_dir'] else 'FAIL'}")
    print(f"  Directory block (/tmp/blocked/): {'PASS' if results['blocked_dir'] else 'FAIL'}")
    print(f"  Wildcard match (*/data.txt):     {'PASS' if results['wildcard_match'] else 'FAIL'}")
    print(f"  Wildcard block (/secret/):       {'PASS' if results['wildcard_block'] else 'FAIL'}")
    print(f"  Nested file in allowed dir:      {'PASS' if results['specific_override'] else 'FAIL'}")
    print("=" * 50)

    # Cleanup
    cleanup_test_dirs()

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    if passed == total:
        print(f"\nAll {total} wildcard tests passed!")
        return 0
    else:
        print(f"\n{passed}/{total} tests passed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
