// Use kernel BTF types from vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Protocol and socket constants
#define PROTO_TCP 6
#define PROTO_UDP 17
#define AF_INET 2
#define AF_INET6 10

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

// =============================================================================
// Path Matching State Machine
// =============================================================================
// Based on LPC 2025 presentation approach:
// - Walk dentry tree from file to root
// - Use state machine for pattern matching
// - State transitions based on path component hash
// - Supports wildcards and hierarchical patterns

#define MAX_PATH_DEPTH 32       // Max directory depth to walk
#define PATH_STATE_ROOT 0       // Starting state
#define PATH_STATE_ACCEPT 0xFFFFFFFE  // Accept (allow)
#define PATH_STATE_REJECT 0xFFFFFFFF  // Reject (deny)

// State transition key: current_state + component_hash -> next_state
struct path_state_key {
    u32 role_id;
    u32 state;           // Current state
    u32 component_hash;  // Hash of path component (e.g., "var", "www")
};

// State transition value
struct path_state_value {
    u32 next_state;      // Next state after this component
    u8 is_terminal;      // 1 if this is a final decision
    u8 decision;         // If terminal: 1=allow, 0=deny
    u8 wildcard;         // 1 if this matches any component (like *)
    u8 _pad;
};

// Path state machine transitions
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct path_state_key);
    __type(value, struct path_state_value);
} path_states SEC(".maps");

// Inode cache: inode -> cached decision (for performance)
struct inode_cache_key {
    u32 role_id;
    u64 inode;
};

struct inode_cache_value {
    u8 decision;      // 1=allow, 0=deny
    u8 _pad[3];
    u32 generation;   // Cache generation for invalidation
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct inode_cache_key);
    __type(value, struct inode_cache_value);
} inode_cache SEC(".maps");

// Global cache generation counter (incremented on mount changes)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} cache_generation SEC(".maps");

// Legacy path_rules map (kept for compatibility)
#define PATH_RULE_MAX_LEN 256

struct path_rule_key {
    u32 role_id;
    u64 path_hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct path_rule_key);
    __type(value, u8);
} path_rules SEC(".maps");

// Auto-enrollment by executable inode
struct exec_enrollment_value {
    u64 pod_id;
    u32 role_id;
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // inode number of executable
    __type(value, struct exec_enrollment_value);
} exec_enrollment SEC(".maps");

// Auto-enrollment by cgroup (cgroup id -> enrollment)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // cgroup id
    __type(value, struct exec_enrollment_value);
} cgroup_enrollment SEC(".maps");

// =============================================================================
// Audit Events (Perf Buffer for systemd-journald integration)
// =============================================================================
// Used in daemonless mode - events are picked up by journald or logging daemon

// Hook types for audit events
#define AUDIT_HOOK_FILE_OPEN      1
#define AUDIT_HOOK_SOCKET_BIND    2
#define AUDIT_HOOK_SOCKET_CONNECT 3
#define AUDIT_HOOK_BPRM_CHECK     4
#define AUDIT_HOOK_PATH_RENAME    5

// Decision types
#define AUDIT_DECISION_DENY  0
#define AUDIT_DECISION_ALLOW 1

struct audit_event {
    u64 timestamp;       // ktime_get_ns()
    u32 pid;             // Process ID
    u32 role_id;         // Role of the process
    u32 decision;        // AUDIT_DECISION_DENY or AUDIT_DECISION_ALLOW
    u32 hook_type;       // AUDIT_HOOK_* value
    u64 context;         // Hook-specific: inode, port, etc.
    u64 pod_id;          // Pod ID
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} audit_events SEC(".maps");

// Helper to emit audit event
static __always_inline void emit_audit_event(void *ctx, u32 pid, u32 role_id,
                                              u64 pod_id, u32 decision,
                                              u32 hook_type, u64 context)
{
    struct audit_event event = {
        .timestamp = bpf_ktime_get_ns(),
        .pid = pid,
        .role_id = role_id,
        .pod_id = pod_id,
        .decision = decision,
        .hook_type = hook_type,
        .context = context,
    };

    bpf_perf_event_output(ctx, &audit_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
}

// Per-CPU buffer for collecting path components (bottom-up)
#define MAX_COMPONENTS 16
#define MAX_COMPONENT_LEN 64

struct path_components {
    u32 hashes[MAX_COMPONENTS];  // Hash of each component
    u8 count;                     // Number of components collected
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct path_components);
} path_buf SEC(".maps");

// Simple hash for path component (djb2 variant)
static __always_inline u32 hash_component(const unsigned char *name, u32 len)
{
    u32 hash = 5381;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= len)
            break;
        unsigned char c = 0;
        bpf_probe_read_kernel(&c, 1, &name[i]);
        if (c == 0)
            break;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Walk dentry tree and collect path component hashes (bottom-up)
static __always_inline int collect_path_components(struct dentry *dentry, struct path_components *buf)
{
    struct dentry *current = dentry;
    struct dentry *parent = NULL;
    buf->count = 0;

    #pragma unroll
    for (int i = 0; i < MAX_COMPONENTS; i++) {
        if (!current)
            break;

        // Bounds check for verifier
        if (buf->count >= MAX_COMPONENTS)
            break;

        // Read parent pointer using CO-RE
        parent = BPF_CORE_READ(current, d_parent);

        // If parent == current, we've reached root
        if (parent == current)
            break;

        // Read d_name using CO-RE
        u32 len = BPF_CORE_READ(current, d_name.len);
        const unsigned char *name = BPF_CORE_READ(current, d_name.name);

        if (len > 0 && name) {
            // Use local index for verifier
            u8 idx = buf->count;
            if (idx < MAX_COMPONENTS) {
                buf->hashes[idx] = hash_component(name, len);
                buf->count = idx + 1;
            }
        }

        current = parent;
    }

    return buf->count;
}

// Run state machine on collected path components (reversed, root-to-leaf)
static __always_inline int check_path_state_machine(u32 role_id, struct path_components *buf)
{
    if (buf->count == 0)
        return 0;  // No rule

    u32 state = PATH_STATE_ROOT;
    struct path_state_key key = {
        .role_id = role_id,
        .state = 0,
        .component_hash = 0,
    };

    u8 count = buf->count;
    if (count > MAX_COMPONENTS)
        count = MAX_COMPONENTS;

    // Walk from root to leaf (reverse order since we collected bottom-up)
    // hashes[count-1] is the topmost dir (closest to root)
    // hashes[0] is the filename
    #pragma unroll
    for (int i = 0; i < MAX_COMPONENTS; i++) {
        if (i >= count)
            break;

        // Index from end to start (root to file)
        int idx = count - 1 - i;
        if (idx < 0)
            break;

        key.state = state;
        key.component_hash = buf->hashes[idx];

        struct path_state_value *val = bpf_map_lookup_elem(&path_states, &key);

        if (!val) {
            // Try wildcard match (component_hash = 0 means match any)
            key.component_hash = 0;
            val = bpf_map_lookup_elem(&path_states, &key);
        }

        if (!val) {
            // No transition, no rule
            return 0;
        }

        if (val->is_terminal) {
            return val->decision ? 1 : -13;
        }

        state = val->next_state;
    }

    // Reached end without terminal state - check if current state is accepting
    key.state = state;
    key.component_hash = 0;  // End-of-path marker
    struct path_state_value *final = bpf_map_lookup_elem(&path_states, &key);
    if (final && final->is_terminal) {
        return final->decision ? 1 : -13;
    }

    return 0;  // No rule matched
}

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
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN, 0);
        return -13;
    }

    // Get dentry from file->f_path using CO-RE
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);

    if (dentry) {
        // Get current cache generation
        u32 zero = 0;
        u32 *gen_ptr = bpf_map_lookup_elem(&cache_generation, &zero);
        u32 current_gen = gen_ptr ? *gen_ptr : 0;

        // Check inode cache first
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);

        if (inode) {
            struct inode_cache_key cache_key = {
                .role_id = info->role_id,
                .inode = (u64)inode,
            };
            struct inode_cache_value *cached = bpf_map_lookup_elem(&inode_cache, &cache_key);
            if (cached && cached->generation == current_gen) {
                // Cache hit with valid generation
                if (cached->decision)
                    return 0;  // Allow
                emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                                 AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN, cache_key.inode);
                return -13;    // Deny
            }
        }

        // Get per-CPU path buffer
        struct path_components *buf = bpf_map_lookup_elem(&path_buf, &zero);

        if (buf) {
            // Collect path components by walking dentry tree
            collect_path_components(dentry, buf);

            // Run state machine
            int result = check_path_state_machine(info->role_id, buf);

            if (result != 0) {
                // Cache the decision with current generation
                if (inode) {
                    struct inode_cache_key cache_key = {
                        .role_id = info->role_id,
                        .inode = (u64)inode,
                    };
                    struct inode_cache_value val = {
                        .decision = (result == 1) ? 1 : 0,
                        .generation = current_gen,
                    };
                    bpf_map_update_elem(&inode_cache, &cache_key, &val, 0);
                }

                if (result == 1) {
                    return 0;   // Explicit allow
                }
                emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                                 AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN,
                                 inode ? (u64)inode : 0);
                return -13;     // Explicit deny
            }
        }
    }

    // No path rule matched - fall back to role_flags
    if (!(*flags & 0x01)) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN, 0);
        return -13;  // File access blocked by role
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
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    // Check role_flags first (bit 1 = network allowed)
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_BIND, 0);
        return -13;
    }

    int result = check_network_access(info->role_id, sock, address, 0);

    if (!(*flags & 0x02)) {
        // Network blocked by role - only allow if explicit allow rule (result=1)
        if (result == 1) {
            return 0;  // Explicit allow overrides role_flags
        }
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_BIND, 0);
        return -13;  // No rule or explicit deny -> block
    }

    // Network allowed by role - only block if explicit deny rule (result=-13)
    if (result == -13) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_BIND, 0);
        return -13;  // Explicit deny overrides role_flags
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    // Check role_flags first (bit 1 = network allowed)
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, 0);
        return -13;
    }

    int result = check_network_access(info->role_id, sock, address, 1);

    if (!(*flags & 0x02)) {
        // Network blocked by role - only allow if explicit allow rule (result=1)
        if (result == 1) {
            return 0;  // Explicit allow overrides role_flags
        }
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, 0);
        return -13;  // No rule or explicit deny -> block
    }

    // Network allowed by role - only block if explicit deny rule (result=-13)
    if (result == -13) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, 0);
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

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!info) {
        return 0;
    }

    // If not enrolled, check for auto-enrollment by executable inode
    if (info->pod_id == 0) {
        // Get executable file's inode
        struct file *exe_file = BPF_CORE_READ(bprm, file);
        if (exe_file) {
            struct inode *exe_inode = BPF_CORE_READ(exe_file, f_inode);
            if (exe_inode) {
                u64 ino = BPF_CORE_READ(exe_inode, i_ino);
                struct exec_enrollment_value *enroll = bpf_map_lookup_elem(&exec_enrollment, &ino);
                if (enroll) {
                    // Auto-enroll based on executable
                    info->pod_id = enroll->pod_id;
                    info->role_id = enroll->role_id;
                    info->stack_depth = 0;
                    info->flags = 0;
                }
            }
        }
    }

    // If still not enrolled, check for auto-enrollment by cgroup
    if (info->pod_id == 0) {
        u64 cgroup_id = bpf_get_current_cgroup_id();
        struct exec_enrollment_value *enroll = bpf_map_lookup_elem(&cgroup_enrollment, &cgroup_id);
        if (enroll) {
            // Auto-enroll based on cgroup
            info->pod_id = enroll->pod_id;
            info->role_id = enroll->role_id;
            info->stack_depth = 0;
            info->flags = 0;
        }
    }

    // If still not enrolled, allow execution
    if (info->pod_id == 0) {
        return 0;
    }

    // Check exec permission
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -13;
    }

    if (!(*flags & 0x04)) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -13;
    }

    return 0;
}

// Invalidate inode cache on rename - file path changed but inode stays same
SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    // Get the inode of the file being renamed
    struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!inode)
        return 0;

    // We can't easily iterate and delete all entries for this inode across all roles
    // Instead, increment the global generation counter to invalidate all cached entries
    // This is a simple but effective approach for handling renames
    u32 zero = 0;
    u32 *gen = bpf_map_lookup_elem(&cache_generation, &zero);
    if (gen) {
        __sync_fetch_and_add(gen, 1);
    }

    return 0;  // Always allow rename, just invalidate cache
}

// Invalidate entire cache on mount/unmount - paths may resolve differently
SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data)
{
    // Increment generation to invalidate all cached path decisions
    u32 zero = 0;
    u32 *gen = bpf_map_lookup_elem(&cache_generation, &zero);
    if (gen) {
        __sync_fetch_and_add(gen, 1);
    }

    return 0;  // Always allow mount, just invalidate cache
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
    // Increment generation to invalidate all cached path decisions
    u32 zero = 0;
    u32 *gen = bpf_map_lookup_elem(&cache_generation, &zero);
    if (gen) {
        __sync_fetch_and_add(gen, 1);
    }

    return 0;  // Always allow umount, just invalidate cache
}

char LICENSE[] SEC("license") = "GPL";
