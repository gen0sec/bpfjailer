# Simple task_storage Test

This is a minimal test to verify if task_storage maps can be created on this system.

## What it tests

1. **Minimal task_storage map**: Simplest possible map definition
2. **Simple LSM hook**: One `task_alloc` hook that uses the map
3. **Map creation**: Whether the kernel accepts the map creation

## Build

```bash
cd test_task_storage
cargo build --release
```

## Run

```bash
sudo ./target/release/test-task-storage
```

## Expected Results

### ✅ Success
If you see:
```
✅ SUCCESS: task_storage map created successfully!
✅ Map 'test_task_storage' found in object
✅ Program 'test_task_alloc' found in object
```

Then task_storage works on this system, and the issue is likely in the main bpfjailer code.

### ❌ Failure
If you see:
```
❌ FAILED: System error, errno: 22 (EINVAL: Invalid argument)
```

Then the kernel is rejecting task_storage map creation, which indicates:
- Kernel doesn't support it (needs 5.11+)
- BPF LSM not active
- Kernel bug or configuration issue

## What this tells us

- **If this test passes**: The issue is in the main bpfjailer implementation
- **If this test fails**: The issue is kernel-level, not code-level
