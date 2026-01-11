// Minimal test for task_storage map

// Define types BEFORE including headers
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

// BPF map type definitions
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1U << 0)

// Helper macros (must be defined before including headers)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define SEC(name) __attribute__((section(name), used))

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Forward declaration
struct task_struct {};

// Simple value structure
struct test_value {
    __u64 counter;
    __u32 flags;
};

// Minimal task_storage map
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct test_value);
} test_task_storage SEC(".maps");

// Simple LSM hook to test task_storage
SEC("lsm/task_alloc")
int BPF_PROG(test_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    // Use bpf_get_current_task_btf() for BTF-typed task pointer
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    // Try to get task storage
    struct test_value *val = (struct test_value *)bpf_task_storage_get(
        &test_task_storage,
        current_task,
        NULL,
        BPF_LOCAL_STORAGE_GET_F_CREATE
    );

    if (val) {
        val->counter = 1;
        val->flags = 0;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
