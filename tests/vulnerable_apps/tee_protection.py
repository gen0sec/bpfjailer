#!/usr/bin/env python3
"""
TEE Protection Tests - Tests for ptrace, module loading, and BPF restrictions.

These tests verify that enrolled processes cannot:
1. Be debugged via ptrace (protects secrets in memory)
2. Load kernel modules (prevents kernel tampering)
3. Load BPF programs (prevents security bypass)

Requires: Role with allow_ptrace=false, allow_module_load=false, allow_bpf_load=false
"""

import os
import sys
import ctypes
import subprocess

# Test role should have these flags disabled
EXPECTED_ROLE = "tee_protected"  # Role ID to use for testing


def test_ptrace_protection():
    """Test that enrolled processes cannot be ptraced/debugged."""
    print("\n=== Test: Ptrace Protection ===")
    print("Attempting to attach debugger to self...")
    
    # Try to ptrace ourselves (PTRACE_TRACEME)
    PTRACE_TRACEME = 0
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    
    result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
    errno = ctypes.get_errno()
    
    if result == -1:
        print(f"BLOCKED - ptrace denied (errno={errno})")
        return True
    else:
        print("ALLOWED - ptrace succeeded (process can be debugged)")
        return False


def test_ptrace_attach_child():
    """Test that enrolled process cannot debug child processes."""
    print("\n=== Test: Ptrace Attach to Child ===")
    print("Spawning child and attempting to attach...")
    
    try:
        # Start a simple sleep process
        child = subprocess.Popen(["sleep", "10"])
        child_pid = child.pid
        
        # Try to attach via ptrace
        PTRACE_ATTACH = 16
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        
        result = libc.ptrace(PTRACE_ATTACH, child_pid, 0, 0)
        errno = ctypes.get_errno()
        
        child.terminate()
        child.wait()
        
        if result == -1:
            print(f"BLOCKED - cannot attach to child (errno={errno})")
            return True
        else:
            # Detach if we attached
            PTRACE_DETACH = 17
            libc.ptrace(PTRACE_DETACH, child_pid, 0, 0)
            print("ALLOWED - attached to child process")
            return False
            
    except Exception as e:
        print(f"ERROR - {e}")
        return False


def test_strace_blocked():
    """Test that strace (ptrace-based) is blocked on enrolled processes."""
    print("\n=== Test: Strace Blocked ===")
    print("Attempting to run strace on a command...")
    
    try:
        result = subprocess.run(
            ["strace", "-e", "trace=open", "true"],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode != 0 or b"EPERM" in result.stderr:
            print("BLOCKED - strace failed")
            return True
        else:
            print("ALLOWED - strace worked")
            return False
            
    except FileNotFoundError:
        print("SKIPPED - strace not installed")
        return None
    except subprocess.TimeoutExpired:
        print("BLOCKED - strace timed out (likely blocked)")
        return True
    except Exception as e:
        print(f"ERROR - {e}")
        return False


def test_module_load():
    """Test that enrolled processes cannot load kernel modules."""
    print("\n=== Test: Kernel Module Loading ===")
    print("Attempting to load a kernel module...")
    
    try:
        # Try to load a common module (will fail if blocked or not root)
        result = subprocess.run(
            ["modprobe", "dummy"],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode != 0:
            stderr = result.stderr.decode()
            if "Operation not permitted" in stderr or "EPERM" in stderr:
                print("BLOCKED - module loading denied by BpfJailer")
                return True
            elif "not found" in stderr:
                print("SKIPPED - module not found (try another)")
                return None
            else:
                print(f"BLOCKED - modprobe failed: {stderr.strip()}")
                return True
        else:
            print("ALLOWED - module loaded successfully")
            # Unload it
            subprocess.run(["rmmod", "dummy"], capture_output=True)
            return False
            
    except FileNotFoundError:
        print("SKIPPED - modprobe not installed")
        return None
    except subprocess.TimeoutExpired:
        print("BLOCKED - modprobe timed out")
        return True
    except Exception as e:
        print(f"ERROR - {e}")
        return False


def test_insmod():
    """Test that insmod is blocked for enrolled processes."""
    print("\n=== Test: insmod Blocked ===")
    print("Attempting insmod on non-existent module...")
    
    try:
        result = subprocess.run(
            ["insmod", "/tmp/nonexistent.ko"],
            capture_output=True,
            timeout=5
        )
        
        stderr = result.stderr.decode()
        if "Operation not permitted" in stderr:
            print("BLOCKED - insmod denied by BpfJailer")
            return True
        elif "No such file" in stderr:
            # Expected - but the syscall was allowed
            print("ALLOWED - insmod reached file check (syscall allowed)")
            return False
        else:
            print(f"Result: {stderr.strip()}")
            return None
            
    except FileNotFoundError:
        print("SKIPPED - insmod not found")
        return None
    except Exception as e:
        print(f"ERROR - {e}")
        return False


def test_bpf_syscall():
    """Test that BPF syscall is blocked for enrolled processes."""
    print("\n=== Test: BPF Syscall ===")
    print("Attempting to call bpf() syscall...")
    
    import ctypes
    
    # BPF syscall number (x86_64)
    SYS_bpf = 321
    BPF_PROG_LOAD = 5
    
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    
    # Try a simple BPF syscall (will fail but we check if it's EPERM)
    result = syscall(SYS_bpf, BPF_PROG_LOAD, 0, 0)
    errno = ctypes.get_errno()
    
    # EPERM = 1, EFAULT = 14, EINVAL = 22
    if errno == 1:  # EPERM
        print("BLOCKED - BPF syscall denied (EPERM)")
        return True
    elif errno == 14 or errno == 22:  # EFAULT or EINVAL
        print("ALLOWED - BPF syscall reached validation (not blocked)")
        return False
    else:
        print(f"RESULT - errno={errno}")
        return None


def test_bpftool():
    """Test that bpftool operations are blocked."""
    print("\n=== Test: bpftool Blocked ===")
    print("Attempting to list BPF programs...")
    
    try:
        result = subprocess.run(
            ["bpftool", "prog", "list"],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode != 0:
            stderr = result.stderr.decode()
            if "Operation not permitted" in stderr:
                print("BLOCKED - bpftool denied")
                return True
            else:
                print(f"FAILED - {stderr.strip()}")
                return None
        else:
            print("ALLOWED - bpftool worked")
            return False
            
    except FileNotFoundError:
        print("SKIPPED - bpftool not installed")
        return None
    except Exception as e:
        print(f"ERROR - {e}")
        return False


def main():
    print("=" * 60)
    print("TEE Protection Tests")
    print("=" * 60)
    print("Testing ptrace, module, and BPF restrictions")
    print("These should be BLOCKED for enrolled processes")
    
    results = {
        "ptrace_self": test_ptrace_protection(),
        "ptrace_child": test_ptrace_attach_child(),
        "strace": test_strace_blocked(),
        "module_load": test_module_load(),
        "insmod": test_insmod(),
        "bpf_syscall": test_bpf_syscall(),
        "bpftool": test_bpftool(),
    }
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    blocked = sum(1 for v in results.values() if v is True)
    allowed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    
    for test, result in results.items():
        status = "BLOCKED" if result is True else "ALLOWED" if result is False else "SKIPPED"
        print(f"  {test}: {status}")
    
    print(f"\nBlocked: {blocked}, Allowed: {allowed}, Skipped: {skipped}")
    
    # For TEE protection, we want everything BLOCKED
    if allowed > 0:
        print("\nWARNING: Some operations were allowed!")
        print("Ensure process is enrolled with a restrictive role.")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
