#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct process_info {
    u64 pod_id;
    u32 role_id;
    u8 stack_depth;
    u8 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct process_info);
} task_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);
} pod_to_role SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(process_tracking_task_alloc, struct task_struct *task, unsigned long clone_flags, u64 stack_start)
{
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!info) {
        return 0;
    }

    // Try to inherit from parent (for fork/clone)
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct process_info *parent_info = bpf_task_storage_get(&task_storage, current_task, NULL, 0);

    if (parent_info && parent_info->pod_id != 0) {
        // Inherit from parent
        info->pod_id = parent_info->pod_id;
        info->role_id = parent_info->role_id;
        info->stack_depth = parent_info->stack_depth;
        info->flags = parent_info->flags;
    } else {
        // Initialize new task
        info->pod_id = 0;
        info->role_id = 0;
        info->stack_depth = 0;
        info->flags = 0;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
