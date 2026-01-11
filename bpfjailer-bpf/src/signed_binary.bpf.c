#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} verified_binaries SEC(".maps");

SEC("lsm/mmap_file")
int BPF_PROG(signed_binary_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
