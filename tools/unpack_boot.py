#!/usr/bin/env python3
"""Unpack Android boot.img with support for v0-v4 headers."""

import struct
import os
import gzip
import lzma
import sys

try:
    import zstandard as zstd
except ImportError:
    zstd = None

try:
    import lz4.block as lz4_block
    import lz4.frame as lz4_frame
except ImportError:
    lz4_block = None
    lz4_frame = None

BOOT_MAGIC = b"ANDROID!"

def page_align(val, page_size=4096):
    return ((val + page_size - 1) // page_size) * page_size

def decompress_ramdisk(data):
    """Try to decompress ramdisk data."""
    # LZ4 legacy (Android format) - most common
    if lz4_block is not None:
        # Android boot ramdisk LZ4 format:
        #   4 bytes magic (0x184C2102)
        #   4 bytes legacy header / compressed size
        #   ... LZ4 block data
        for skip in [4, 8, 12]:
            try:
                return lz4_block.decompress(data[skip:], uncompressed_size=len(data) * 20)
            except Exception:
                pass
        try:
            return lz4_frame.decompress(data)
        except Exception:
            pass

    # gzip - common on older devices
    try:
        return gzip.decompress(data)
    except Exception:
        pass

    # raw deflate
    try:
        import zlib
        return zlib.decompress(data)
    except Exception:
        pass

    # zstandard
    if zstd is not None:
        try:
            return zstd.decompress(data)
        except Exception:
            pass

    # lzma/xz
    try:
        return lzma.decompress(data)
    except Exception:
        pass

    return None

def main():
    boot_img = "boot.img"
    out_dir = "boot_unpacked"

    os.makedirs(out_dir, exist_ok=True)

    with open(boot_img, "rb") as f:
        full_data = f.read()

    if full_data[:8] != BOOT_MAGIC:
        raise ValueError("Not an Android boot image")

    # Read header version at offset 40
    header_version = struct.unpack_from("<I", full_data, 40)[0]

    if header_version in (3, 4):
        # v3/v4 layout:
        # 0-7: magic
        # 8-11: kernel_size
        # 12-15: ramdisk_size
        # 16-19: os_version
        # 20-23: header_size
        # 24-39: reserved[4]
        # 40-43: header_version
        kernel_size = struct.unpack_from("<I", full_data, 8)[0]
        ramdisk_size = struct.unpack_from("<I", full_data, 12)[0]
        os_version = struct.unpack_from("<I", full_data, 16)[0]
        header_size = struct.unpack_from("<I", full_data, 20)[0]

        print("=" * 60)
        print(f"Android Boot Image v{header_version}")
        print("=" * 60)
        print(f"  kernel_size:  {kernel_size} bytes ({kernel_size / 1024:.1f} KB)")
        print(f"  ramdisk_size: {ramdisk_size} bytes ({ramdisk_size / 1024:.1f} KB)")
        print(f"  os_version:   0x{os_version:08x}")
        print(f"  header_size:  {header_size}")
        print(f"  total file:   {len(full_data)} bytes ({len(full_data) / 1024 / 1024:.1f} MB)")

        # v3/v4: page size is always 4096
        page_size = 4096

        # Header occupies at least one page
        header_pages = page_align(max(header_size, 1), page_size)
        kernel_offset = header_pages
        kernel_data = full_data[kernel_offset:kernel_offset + kernel_size]

        ramdisk_offset = page_align(kernel_offset + kernel_size, page_size)
        ramdisk_data = full_data[ramdisk_offset:ramdisk_offset + ramdisk_size]

        print(f"\nLayout:")
        print(f"  header:  0x00000000 - 0x{kernel_offset:08x}")
        print(f"  kernel:  0x{kernel_offset:08x} - 0x{kernel_offset + kernel_size:08x}")
        print(f"  ramdisk: 0x{ramdisk_offset:08x} - 0x{ramdisk_offset + ramdisk_size:08x}")

        # v4 may have a vendor boot signature at the end - ignore for extraction
    else:
        # v0/v1/v2 layout
        kernel_size = struct.unpack_from("<I", full_data, 8)[0]
        kernel_addr = struct.unpack_from("<I", full_data, 12)[0]
        ramdisk_size = struct.unpack_from("<I", full_data, 16)[0]
        ramdisk_addr = struct.unpack_from("<I", full_data, 20)[0]
        second_size = struct.unpack_from("<I", full_data, 24)[0]
        second_addr = struct.unpack_from("<I", full_data, 28)[0]
        tags_addr = struct.unpack_from("<I", full_data, 32)[0]
        page_size = struct.unpack_from("<I", full_data, 36)[0]
        os_version = struct.unpack_from("<I", full_data, 44)[0] if header_version >= 1 else 0

        print("=" * 60)
        print(f"Android Boot Image v{header_version}")
        print("=" * 60)
        print(f"  kernel_size:  {kernel_size} bytes ({kernel_size / 1024:.1f} KB)")
        print(f"  kernel_addr:  0x{kernel_addr:08x}")
        print(f"  ramdisk_size: {ramdisk_size} bytes ({ramdisk_size / 1024:.1f} KB)")
        print(f"  ramdisk_addr: 0x{ramdisk_addr:08x}")
        print(f"  second_size:  {second_size}")
        print(f"  tags_addr:    0x{tags_addr:08x}")
        print(f"  page_size:    {page_size}")

        if page_size == 0:
            page_size = 2048
            print(f"  [corrected page_size to {page_size}]")

        header_offset = 0
        kernel_offset = page_align(header_offset + page_size, page_size)
        kernel_data = full_data[kernel_offset:kernel_offset + kernel_size]

        ramdisk_offset = page_align(kernel_offset + kernel_size, page_size)
        ramdisk_data = full_data[ramdisk_offset:ramdisk_offset + ramdisk_size]

        second_offset = page_align(ramdisk_offset + ramdisk_size, page_size)
        second_data = full_data[second_offset:second_offset + second_size]

        dt_size = 0
        if header_version == 0:
            dt_size = struct.unpack_from("<I", full_data, 40)[0]
        if header_version >= 2:
            dt_size = struct.unpack_from("<I", full_data, 64)[0]

        dtb_offset = page_align(second_offset + second_size, page_size)
        dtb_data = full_data[dtb_offset:dtb_offset + dt_size] if dt_size > 0 else b""

        print(f"\nLayout:")
        print(f"  kernel:  0x{kernel_offset:08x}")
        print(f"  ramdisk: 0x{ramdisk_offset:08x}")
        if second_size > 0:
            print(f"  second:  0x{second_offset:08x}")
        if dt_size > 0:
            print(f"  dtb:     0x{dtb_offset:08x}")

    # Save kernel
    kernel_path = os.path.join(out_dir, "kernel")
    with open(kernel_path, "wb") as f:
        f.write(kernel_data)
    print(f"\n[+] Kernel saved: {kernel_path} ({len(kernel_data)} bytes)")

    # Check if kernel is compressed
    if kernel_data[:4] == b'\x7fELF':
        print(f"    Kernel format: ELF (raw Linux kernel)")
    elif kernel_data[:2] == b'\x1f\x8b':
        print(f"    Kernel format: gzip compressed")
    elif kernel_data[:2] == b'\xfd7':
        print(f"    Kernel format: XZ compressed")
    elif kernel_data[:4] == b'\x89LZO':
        print(f"    Kernel format: LZO compressed")
    elif kernel_data[:3] == b'\x02\x21\x4c':
        print(f"    Kernel format: LZ4 compressed")
    else:
        print(f"    Kernel format: unknown (magic: {kernel_data[:8].hex()})")

    # Save ramdisk
    ramdisk_path = os.path.join(out_dir, "ramdisk.img")
    with open(ramdisk_path, "wb") as f:
        f.write(ramdisk_data)
    print(f"[+] Ramdisk saved: {ramdisk_path} ({len(ramdisk_data)} bytes)")

    # Decompress ramdisk
    print(f"\n--- Decompressing ramdisk ---")
    decompressed = decompress_ramdisk(ramdisk_data)
    if decompressed:
        cpio_path = os.path.join(out_dir, "ramdisk.cpio")
        with open(cpio_path, "wb") as f:
            f.write(decompressed)
        print(f"[+] Decompressed: {cpio_path} ({len(decompressed)} bytes)")

        # Extract cpio
        ramdisk_dir = os.path.join(out_dir, "ramdisk")
        os.makedirs(ramdisk_dir, exist_ok=True)
        cpio_abs = os.path.abspath(cpio_path).replace("\\", "/")
        ramdisk_abs = os.path.abspath(ramdisk_dir).replace("\\", "/")

        # Use cpio command via bash
        os.system(f'cd "{ramdisk_dir}" && cpio -idmu --no-absolute-filenames < "{cpio_abs}" 2>&1')
        entries = os.listdir(ramdisk_dir)
        if entries:
            print(f"[+] Ramdisk extracted: {ramdisk_dir} ({len(entries)} entries)")
        else:
            # Try Python-based cpio extraction
            print("[!] cpio command failed, trying Python extraction...")
            import io
            import stat as st
            fio = io.BytesIO(decompressed)
            while True:
                # cpio newc format header
                magic = fio.read(6)
                if not magic or magic == b'TRAILER':
                    break
                if magic != b'070701':
                    print(f"    Bad cpio magic: {magic}")
                    break
                # Read the full newc header (110 bytes total including magic)
                header = magic + fio.read(104)
                ino = int(header[6:14], 16)
                mode = int(header[14:22], 16)
                uid = int(header[22:30], 16)
                gid = int(header[30:38], 16)
                nlink = int(header[38:46], 16)
                mtime = int(header[46:54], 16)
                filesize = int(header[54:62], 16)
                dev_major = int(header[62:70], 16)
                dev_minor = int(header[70:78], 16)
                rdev_major = int(header[78:86], 16)
                rdev_minor = int(header[86:94], 16)
                namesize = int(header[94:102], 16)
                check = int(header[102:110], 16)

                name = fio.read(namesize).rstrip(b'\x00').decode('utf-8', errors='replace')
                # Pad to 4-byte alignment
                fio.read((-(6 + 104 + namesize) % 4))

                if name in ('.', 'TRAILER!!!'):
                    fio.read((-(filesize) % 4) + filesize)
                    continue

                target = os.path.join(ramdisk_dir, name.lstrip('/'))
                if mode & 0o170000 == 0o040000:  # directory
                    os.makedirs(target, exist_ok=True)
                elif mode & 0o170000 == 0o120000:  # symlink
                    link_data = fio.read(filesize)
                    link_target = link_data.rstrip(b'\x00').decode('utf-8', errors='replace')
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    from pathlib import Path
                    try:
                        Path(target).symlink_to(link_target)
                    except Exception:
                        pass
                    fio.read((-(filesize) % 4))
                elif mode & 0o170000 == 0o100000:  # regular file
                    file_data = fio.read(filesize)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, 'wb') as f:
                        f.write(file_data)
                    if mode & 0o111 != 0:
                        os.chmod(target, 0o755)
                    fio.read((-(filesize) % 4))
                else:
                    fio.read((-(filesize) % 4) + filesize)
            print(f"[+] Ramdisk extracted: {ramdisk_dir}")
    else:
        print("[!] Could not decompress ramdisk")
        print(f"    First 32 bytes hex: {ramdisk_data[:32].hex()}")
        # Try to identify
        header_bytes = ramdisk_data[:32]
        if header_bytes[:2] == b'\x1f\x8b':
            print("    Looks like gzip")
        elif header_bytes[:3] == b'\x02\x21\x4c':
            print("    Looks like LZ4")
        elif header_bytes[:4] == b'\x28\xb5\x2f\xfd':
            print("    Looks like zstd")
        elif header_bytes[:5] == b'\xfd7zXZ':
            print("    Looks like XZ")

    # If v0, also save second and dtb
    if header_version not in (3, 4) and 'second_size' in dir() and second_size > 0:
        second_path = os.path.join(out_dir, "second.img")
        with open(second_path, "wb") as f:
            f.write(second_data)
        print(f"[+] Second saved: {second_path} ({len(second_data)} bytes)")

    if header_version not in (3, 4) and 'dtb_data' in dir() and len(dtb_data) > 0:
        dtb_path = os.path.join(out_dir, "dtb.img")
        with open(dtb_path, "wb") as f:
            f.write(dtb_data)
        print(f"[+] DTB saved: {dtb_path} ({len(dtb_data)} bytes)")

    print(f"\nDone! Output in: {out_dir}/")

if __name__ == "__main__":
    main()
