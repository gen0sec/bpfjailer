#!/bin/bash
# Script to check kernel support for task_storage maps

echo "=== Kernel Support Check for task_storage Maps ==="
echo ""

# 1. Kernel version check
echo "1. Kernel Version:"
KERNEL_VERSION=$(uname -r)
echo "   Current: $KERNEL_VERSION"

# Extract major.minor version
MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$MAJOR" -gt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -ge 11 ]); then
    echo "   ✅ Kernel version supports task_storage (needs 5.11+)"
else
    echo "   ❌ Kernel version too old (needs 5.11+, you have ${MAJOR}.${MINOR})"
fi
echo ""

# 2. Check BPF LSM is active
echo "2. BPF LSM Status:"
if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    echo "   Active LSMs: $LSM_LIST"
    if echo "$LSM_LIST" | grep -q "bpf"; then
        echo "   ✅ BPF LSM is active"
    else
        echo "   ❌ BPF LSM is NOT active (bpf not in LSM list)"
        echo "   💡 Enable with: security=apparmor,bpf (in kernel boot params)"
    fi
else
    echo "   ⚠️  Cannot check LSM status (/sys/kernel/security/lsm not found)"
fi
echo ""

# 3. Check kernel config
echo "3. Kernel Configuration:"
if [ -f /proc/config.gz ]; then
    echo "   Checking /proc/config.gz..."
    if zcat /proc/config.gz | grep -q "^CONFIG_BPF=y\|^CONFIG_BPF=m"; then
        echo "   ✅ CONFIG_BPF is enabled"
    else
        echo "   ❌ CONFIG_BPF is not enabled"
    fi

    if zcat /proc/config.gz | grep -q "^CONFIG_BPF_LSM=y"; then
        echo "   ✅ CONFIG_BPF_LSM is enabled"
    else
        echo "   ❌ CONFIG_BPF_LSM is not enabled"
    fi

    if zcat /proc/config.gz | grep -q "^CONFIG_BPF_SYSCALL=y"; then
        echo "   ✅ CONFIG_BPF_SYSCALL is enabled"
    else
        echo "   ❌ CONFIG_BPF_SYSCALL is not enabled"
    fi
elif [ -f /boot/config-$(uname -r) ]; then
    CONFIG_FILE="/boot/config-$(uname -r)"
    echo "   Checking $CONFIG_FILE..."
    if grep -q "^CONFIG_BPF=y\|^CONFIG_BPF=m" "$CONFIG_FILE"; then
        echo "   ✅ CONFIG_BPF is enabled"
    else
        echo "   ❌ CONFIG_BPF is not enabled"
    fi

    if grep -q "^CONFIG_BPF_LSM=y" "$CONFIG_FILE"; then
        echo "   ✅ CONFIG_BPF_LSM is enabled"
    else
        echo "   ❌ CONFIG_BPF_LSM is not enabled"
    fi

    if grep -q "^CONFIG_BPF_SYSCALL=y" "$CONFIG_FILE"; then
        echo "   ✅ CONFIG_BPF_SYSCALL is enabled"
    else
        echo "   ❌ CONFIG_BPF_SYSCALL is not enabled"
    fi
else
    echo "   ⚠️  Cannot find kernel config (checked /proc/config.gz and /boot/config-*)"
fi
echo ""

# 4. Check BPF filesystem
echo "4. BPF Filesystem:"
if mountpoint -q /sys/fs/bpf 2>/dev/null; then
    echo "   ✅ /sys/fs/bpf is mounted"
else
    echo "   ⚠️  /sys/fs/bpf is not mounted (not required for task_storage, but useful)"
fi
echo ""

# 5. Check if bpftool is available
echo "5. BPF Tools:"
if command -v bpftool &> /dev/null; then
    echo "   ✅ bpftool is installed"
    BPFTOOL_VERSION=$(bpftool version 2>/dev/null | head -1)
    echo "   $BPFTOOL_VERSION"
else
    echo "   ⚠️  bpftool not found (optional, but useful for debugging)"
fi
echo ""

# 6. Try to create a test map (if bpftool is available)
if command -v bpftool &> /dev/null; then
    echo "6. Testing task_storage Map Creation:"
    TEST_MAP="/sys/fs/bpf/test_task_storage_check"

    # Clean up any existing test map
    rm -f "$TEST_MAP" 2>/dev/null

    # Try to create a task_storage map
    if bpftool map create "$TEST_MAP" type task_storage key 4 value 16 max_entries 0 flags 1 2>/dev/null; then
        echo "   ✅ SUCCESS: task_storage map created successfully!"
        rm -f "$TEST_MAP" 2>/dev/null
    else
        ERROR=$(bpftool map create "$TEST_MAP" type task_storage key 4 value 16 max_entries 0 flags 1 2>&1)
        echo "   ❌ FAILED: Cannot create task_storage map"
        echo "   Error: $ERROR"
    fi
    echo ""
fi

# 7. Summary
echo "=== Summary ==="
echo ""
echo "For task_storage maps to work, you need:"
echo "  1. Kernel 5.11 or later ✅/❌ (checked above)"
echo "  2. CONFIG_BPF_LSM=y ✅/❌ (checked above)"
echo "  3. BPF LSM active at runtime ✅/❌ (checked above)"
echo "  4. CONFIG_BPF_SYSCALL=y ✅/❌ (checked above)"
echo ""
echo "If all checks pass but maps still fail, it may be:"
echo "  - A kernel bug"
echo "  - Missing kernel module"
echo "  - Additional kernel configuration needed"
echo ""
