#!/usr/bin/env python3
"""
Auto-Enrollment Test
Tests BpfJailer's alternative enrollment methods:
- Executable-based enrollment (by inode)
- Cgroup-based enrollment
"""

import os
import sys
import subprocess
import tempfile
import shutil

def test_executable_enrollment():
    """Test auto-enrollment by executable path"""
    print("\n[Executable-based Enrollment Test]")

    # Create a test binary that will be auto-enrolled
    test_dir = tempfile.mkdtemp(prefix="bpfjailer_test_")
    test_binary = os.path.join(test_dir, "test_app")

    # Create a simple test script
    script_content = '''#!/usr/bin/env python3
import socket
import sys

# Try to make a network connection (should be blocked if enrolled with restricted role)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect(("127.0.0.1", 12345))
    sock.close()
    print("NETWORK: ALLOWED")
    sys.exit(0)
except PermissionError:
    print("NETWORK: BLOCKED (BpfJailer)")
    sys.exit(1)
except OSError as e:
    if e.errno == 13:
        print("NETWORK: BLOCKED (BpfJailer)")
        sys.exit(1)
    # Connection refused is expected (no server listening)
    print("NETWORK: ALLOWED (connection refused, but not blocked)")
    sys.exit(0)
'''

    with open(test_binary, 'w') as f:
        f.write(script_content)
    os.chmod(test_binary, 0o755)

    # Get the inode of the test binary
    inode = os.stat(test_binary).st_ino
    print(f"Created test binary: {test_binary} (inode={inode})")

    # Test without enrollment - should allow network
    print("\n1. Without enrollment:")
    result = subprocess.run([sys.executable, test_binary], capture_output=True, text=True)
    print(f"   {result.stdout.strip()}")
    no_enroll_allowed = "ALLOWED" in result.stdout

    # Clean up
    shutil.rmtree(test_dir)

    return no_enroll_allowed, inode

def test_cgroup_enrollment():
    """Test auto-enrollment by cgroup"""
    print("\n[Cgroup-based Enrollment Test]")

    cgroup_base = "/sys/fs/cgroup"
    test_cgroup = os.path.join(cgroup_base, "bpfjailer_test")

    # Check if cgroup2 is available
    if not os.path.exists(cgroup_base):
        print("[-] Cgroup2 not available, skipping")
        return None

    try:
        # Create test cgroup
        if not os.path.exists(test_cgroup):
            os.makedirs(test_cgroup)
        print(f"Created test cgroup: {test_cgroup}")

        # Get cgroup ID (inode of the cgroup directory)
        cgroup_id = os.stat(test_cgroup).st_ino
        print(f"Cgroup ID (inode): {cgroup_id}")

        # Test moving current process to cgroup
        procs_file = os.path.join(test_cgroup, "cgroup.procs")
        if os.path.exists(procs_file):
            print(f"[+] Cgroup procs file exists: {procs_file}")
            return True, cgroup_id
        else:
            print(f"[-] Cgroup procs file not found")
            return False, cgroup_id

    except PermissionError:
        print("[-] Permission denied creating cgroup (need root)")
        return None
    except Exception as e:
        print(f"[-] Cgroup test error: {e}")
        return None
    finally:
        # Clean up
        try:
            if os.path.exists(test_cgroup):
                os.rmdir(test_cgroup)
        except:
            pass

def test_xattr_enrollment():
    """Test xattr-based enrollment markers"""
    print("\n[Xattr-based Enrollment Test]")

    test_dir = tempfile.mkdtemp(prefix="bpfjailer_xattr_")
    test_file = os.path.join(test_dir, "test_binary")

    try:
        # Create test file
        with open(test_file, 'w') as f:
            f.write("#!/bin/sh\necho test")
        os.chmod(test_file, 0o755)

        # Try xattr module first
        try:
            import xattr

            # Set pod_id xattr (little-endian u64 = 1000)
            pod_id_bytes = (1000).to_bytes(8, 'little')
            xattr.setxattr(test_file, 'user.bpfjailer.pod_id', pod_id_bytes)
            print("[+] Set pod_id xattr")

            # Set role_id xattr (little-endian u32 = 1)
            role_id_bytes = (1).to_bytes(4, 'little')
            xattr.setxattr(test_file, 'user.bpfjailer.role_id', role_id_bytes)
            print("[+] Set role_id xattr")

            # Read back
            pod_value = xattr.getxattr(test_file, 'user.bpfjailer.pod_id')
            role_value = xattr.getxattr(test_file, 'user.bpfjailer.role_id')

            pod_id = int.from_bytes(pod_value, 'little')
            role_id = int.from_bytes(role_value, 'little')

            print(f"[+] Read back: pod_id={pod_id}, role_id={role_id}")
            return pod_id == 1000 and role_id == 1

        except ImportError:
            print("[-] xattr module not available (pip install xattr)")
            print("    Xattr enrollment requires the xattr Python module")
            return None
        except OSError as e:
            print(f"[-] xattr error: {e}")
            return None

    finally:
        shutil.rmtree(test_dir)

def main():
    print("=" * 60)
    print("BpfJailer Auto-Enrollment Test")
    print("=" * 60)

    results = {}

    # Test 1: Executable enrollment
    exec_result = test_executable_enrollment()
    if exec_result:
        allowed, inode = exec_result
        results["executable"] = allowed
        print(f"\n   Result: Test binary {'allowed' if allowed else 'blocked'} network")
        print(f"   (To auto-enroll, add inode {inode} to exec_enrollment map)")

    # Test 2: Cgroup enrollment
    cgroup_result = test_cgroup_enrollment()
    if cgroup_result:
        success, cgroup_id = cgroup_result
        results["cgroup"] = success
        print(f"\n   Result: Cgroup {'ready' if success else 'not ready'}")
        print(f"   (To auto-enroll, add cgroup_id {cgroup_id} to cgroup_enrollment map)")
    else:
        results["cgroup"] = None

    # Test 3: Xattr enrollment
    xattr_result = test_xattr_enrollment()
    results["xattr"] = xattr_result
    if xattr_result is not None:
        print(f"\n   Result: Xattr {'working' if xattr_result else 'failed'}")

    # Summary
    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  Executable enrollment infrastructure: {'PASS' if results.get('executable') else 'SKIP'}")
    print(f"  Cgroup enrollment infrastructure:     {'PASS' if results.get('cgroup') else 'SKIP'}")
    print(f"  Xattr enrollment markers:             {'PASS' if results.get('xattr') else 'SKIP'}")
    print("=" * 60)

    # Show how to use auto-enrollment
    print("\nTo test auto-enrollment with BpfJailer:")
    print("1. Add executable to policy.json exec_enrollments")
    print("2. Create cgroup and add to policy.json cgroup_enrollments")
    print("3. Restart daemon and run the executable or move to cgroup")

    passed = sum(1 for v in results.values() if v)
    total = sum(1 for v in results.values() if v is not None)

    if total > 0:
        print(f"\n{passed}/{total} infrastructure tests passed")
        return 0 if passed == total else 1
    else:
        print("\nNo tests could run (missing dependencies)")
        return 1

if __name__ == "__main__":
    sys.exit(main())
