#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u16);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} allowed_addresses SEC(".maps");

SEC("lsm/socket_bind")
int BPF_PROG(networking_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(networking_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(networking_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    return 0;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(networking_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
