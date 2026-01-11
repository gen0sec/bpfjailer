/* Placeholder for vmlinux.h - should be generated using bpftool */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

struct task_struct {};
struct file {};
struct socket {};
struct sockaddr {};
struct linux_binprm {};
struct msghdr {};

/* BPF map types - must match kernel enum */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1U << 0)

#define SEC(name) __attribute__((section(name), used))
#define BPF_PROG(name, ...) name

#endif
