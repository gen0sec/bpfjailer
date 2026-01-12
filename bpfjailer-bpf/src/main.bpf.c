// Define types before including headers
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
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s64 s64;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// BPF map type definitions
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_MAP_TYPE_HASH 1
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1U << 0)

// Helper macros - these should match libbpf conventions
// Note: __uint creates an array declaration that libbpf parses
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define SEC(name) __attribute__((section(name), used))

// Forward declarations
struct task_struct {};
struct file {};
struct socket {
    short type;  // SOCK_STREAM, SOCK_DGRAM, etc.
};
struct sockaddr {
    unsigned short sa_family;
};
struct linux_binprm {};

// Socket address structures
struct sockaddr_in {
    unsigned short sin_family;
    __be16 sin_port;
    __be32 sin_addr;
    unsigned char __pad[8];
};

struct sockaddr_in6 {
    unsigned short sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

// Address families
#define AF_INET  2
#define AF_INET6 10

// Socket types
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

// Protocol constants
#define PROTO_TCP 6
#define PROTO_UDP 17

#define MAX_STACK_DEPTH 4
#define MAX_PATH_LEN 4096

struct process_info {
    u64 pod_id;
    u32 role_id;
    u8 stack_depth;
    u8 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct process_info));
    __uint(max_entries, 0);
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} role_flags SEC(".maps");

// Network rule key: role_id + port + protocol + direction
// direction: 0 = bind, 1 = connect
struct net_rule_key {
    u32 role_id;
    u16 port;
    u8 protocol;  // PROTO_TCP or PROTO_UDP
    u8 direction; // 0 = bind, 1 = connect
};

// Network rules map: key -> allowed (1) or blocked (0)
// If key not found, falls back to role_flags
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct net_rule_key);
    __type(value, u8);
} network_rules SEC(".maps");

// Pending enrollments: userspace writes here, BPF migrates to task_storage
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);    // PID
    __type(value, struct process_info);
} pending_enrollments SEC(".maps");

// Helper to check and migrate pending enrollment to task_storage
static __always_inline void check_pending_enrollment(struct task_struct *task, u32 pid)
{
    struct process_info *pending = bpf_map_lookup_elem(&pending_enrollments, &pid);
    if (!pending || pending->pod_id == 0) {
        return;
    }

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (info) {
        info->pod_id = pending->pod_id;
        info->role_id = pending->role_id;
        info->stack_depth = pending->stack_depth;
        info->flags = pending->flags;
    }

    // Remove from pending after migration
    bpf_map_delete_elem(&pending_enrollments, &pid);
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags, u64 stack_start)
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

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check for pending enrollment and migrate to task_storage
    check_pending_enrollment(task, pid);

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        return -13;
    }

    if (!(*flags & 0x01)) {
        return -13;
    }

    return 0;
}

// Helper to convert network byte order to host byte order (big endian to little endian)
static __always_inline u16 bpf_ntohs(__be16 val)
{
    return (val >> 8) | (val << 8);
}

// Check network access based on port/protocol rules
// Returns: 1 = explicit allow, 0 = no rule (defer to role_flags), -13 = explicit deny
static __always_inline int check_network_access(u32 role_id, struct socket *sock,
                                                  struct sockaddr *address, u8 direction)
{
    u16 port = 0;
    u8 protocol = 0;

    // Determine protocol from socket type
    short sock_type = 0;
    bpf_probe_read_kernel(&sock_type, sizeof(sock_type), &sock->type);

    if (sock_type == SOCK_STREAM) {
        protocol = PROTO_TCP;
    } else if (sock_type == SOCK_DGRAM) {
        protocol = PROTO_UDP;
    } else {
        // Unknown socket type, fall back to role_flags
        return 0;
    }

    // Extract port from address
    unsigned short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        __be16 be_port = 0;
        bpf_probe_read_kernel(&be_port, sizeof(be_port), &addr4->sin_port);
        port = bpf_ntohs(be_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
        __be16 be_port = 0;
        bpf_probe_read_kernel(&be_port, sizeof(be_port), &addr6->sin6_port);
        port = bpf_ntohs(be_port);
    } else {
        // Unknown address family, no rule
        return 0;
    }

    // Check specific port rule first
    struct net_rule_key key = {
        .role_id = role_id,
        .port = port,
        .protocol = protocol,
        .direction = direction,
    };

    u8 *rule = bpf_map_lookup_elem(&network_rules, &key);
    if (rule) {
        // Specific rule found
        return *rule ? 1 : -13;  // 1 = explicit allow, -13 = explicit deny
    }

    // Check wildcard port rule (port = 0 means all ports)
    key.port = 0;
    rule = bpf_map_lookup_elem(&network_rules, &key);
    if (rule) {
        return *rule ? 1 : -13;
    }

    // No specific rule, fall back to role_flags
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    // Check role_flags first (bit 1 = network allowed)
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        return -13;
    }

    int result = check_network_access(info->role_id, sock, address, 0);

    if (!(*flags & 0x02)) {
        // Network blocked by role - only allow if explicit allow rule (result=1)
        if (result == 1) {
            return 0;  // Explicit allow overrides role_flags
        }
        return -13;  // No rule or explicit deny -> block
    }

    // Network allowed by role - only block if explicit deny rule (result=-13)
    if (result == -13) {
        return -13;  // Explicit deny overrides role_flags
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    // Check role_flags first (bit 1 = network allowed)
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        return -13;
    }

    int result = check_network_access(info->role_id, sock, address, 1);

    if (!(*flags & 0x02)) {
        // Network blocked by role - only allow if explicit allow rule (result=1)
        if (result == 1) {
            return 0;  // Explicit allow overrides role_flags
        }
        return -13;  // No rule or explicit deny -> block
    }

    // Network allowed by role - only block if explicit deny rule (result=-13)
    if (result == -13) {
        return -13;  // Explicit deny overrides role_flags
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check for pending enrollment and migrate to task_storage
    check_pending_enrollment(task, pid);

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        return -13;
    }

    if (!(*flags & 0x04)) {
        return -13;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
