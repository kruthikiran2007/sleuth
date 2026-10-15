"""Build minimal valid PE32 files for Sleuth tests.

Produces a tiny but parseable PE with a configurable import table, section
names/sizes, and extra blob bytes (for secrets/strings tests). Nothing here
is ever executed — these are static fixtures for parser tests only.
"""

import struct


def _build_idata(imports, base_rva):
    """Build the import-directory blob for *imports*.

    imports: dict like {"kernel32.dll": ["CreateRemoteThread", ...]}.
    base_rva: virtual address where this blob will live.
    Returns bytes.
    """
    dll_names = sorted(imports.keys())
    func_lists = {dll: sorted(imports[dll]) for dll in dll_names}
    num_dlls = len(dll_names)
    desc_size = 20 * (num_dlls + 1)

    cur = desc_size
    int_offsets, iat_offsets = {}, {}
    for dll in dll_names:
        n = len(func_lists[dll])
        int_offsets[dll] = cur
        cur += 4 * (n + 1)
        iat_offsets[dll] = cur
        cur += 4 * (n + 1)
    hint_offsets = {}
    for dll in dll_names:
        for fn in func_lists[dll]:
            hint_offsets[(dll, fn)] = cur
            entry = struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(entry) % 2:
                entry += b"\x00"
            cur += len(entry)
    dll_name_offsets = {}
    for dll in dll_names:
        dll_name_offsets[dll] = cur
        cur += len(dll.encode()) + 1

    idata = bytearray(cur)
    for dll in dll_names:
        for i, fn in enumerate(func_lists[dll]):
            fn_rva = base_rva + hint_offsets[(dll, fn)]
            struct.pack_into("<I", idata, int_offsets[dll] + 4 * i, fn_rva)
            struct.pack_into("<I", idata, iat_offsets[dll] + 4 * i, fn_rva)
    for (dll, fn), off in hint_offsets.items():
        entry = struct.pack("<H", 0) + fn.encode() + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"
        idata[off:off + len(entry)] = entry
    for dll, off in dll_name_offsets.items():
        blob = dll.encode() + b"\x00"
        idata[off:off + len(blob)] = blob
    for i, dll in enumerate(dll_names):
        struct.pack_into(
            "<IIIII",
            idata, i * 20,
            base_rva + int_offsets[dll],
            0,
            0,
            base_rva + dll_name_offsets[dll],
            base_rva + iat_offsets[dll],
        )
    return bytes(idata)


def _idata_size(imports):
    """Byte size of the import blob (before file-alignment padding)."""
    dll_names = sorted(imports.keys())
    size = 20 * (len(dll_names) + 1)
    for dll in dll_names:
        n = len(imports[dll])
        size += 8 * (n + 1)
        for fn in imports[dll]:
            entry = 2 + len(fn.encode()) + 1
            if entry % 2:
                entry += 1
            size += entry
        size += len(dll.encode()) + 1
    return size


def build_pe(imports=None, sections=None, extra=b""):
    """Return bytes of a minimal PE32.

    imports: dict like {"kernel32.dll": ["CreateRemoteThread", ...]}.
    sections: list of (name, size, data_byte) tuples; defaults to .text.
    extra: raw bytes appended at the end (for strings/secrets tests).
    """
    imports = imports or {}
    sections = sections or [(".text", 0x200, 0xCC)]

    file_alignment = 0x200
    section_alignment = 0x1000
    size_of_headers = 0x200

    def align_up(n, a):
        return (n + a - 1) // a * a

    # Reserve an .idata section when imports are requested.
    all_sections = list(sections)
    idata_len = 0
    if imports:
        idata_len = _idata_size(imports)
        all_sections.append((".idata", align_up(idata_len, file_alignment), 0))

    # Lay out sections: virtual addresses and raw file offsets.
    virt, raw = 0x1000, size_of_headers
    layout = []  # (name, vsize, vaddr, rawsize, rawptr, fill)
    for name, size, fill in all_sections:
        rawsize = align_up(size, file_alignment)
        layout.append((name, rawsize, virt, rawsize, raw, fill))
        virt += align_up(rawsize, section_alignment)
        raw += rawsize
    size_of_image = align_up(virt, section_alignment)

    # Build the import blob now that its RVA is known.
    idata = b""
    import_dir = (0, 0)
    if imports:
        idata_vaddr = layout[-1][2]
        idata = _build_idata(imports, idata_vaddr)
        import_dir = (idata_vaddr, len(idata))

    # ---- DOS header ----
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)

    # ---- PE signature + COFF header ----
    coff = struct.pack(
        "<HHIIIHH",
        0x14C, len(layout), 0, 0, 0, 0xE0, 0x010F,
    )

    # ---- Optional header (PE32, fixed part = 96 bytes) ----
    optional = struct.pack(
        "<HBBIIIII"
        "I"      # BaseOfData
        "I"      # ImageBase
        "I"      # SectionAlignment
        "I"      # FileAlignment
        "HHHHHH" # OS/image/subsystem versions
        "I"      # Win32VersionValue
        "I"      # SizeOfImage
        "I"      # SizeOfHeaders
        "I"      # CheckSum
        "H"      # Subsystem
        "H"      # DllCharacteristics
        "IIIII"  # stack/heap reserve+commit, LoaderFlags
        "I",     # NumberOfRvaAndSizes
        0x10B,
        0, 0,
        0x200, 0x200, 0,
        0x1000,          # AddressOfEntryPoint
        0x1000,          # BaseOfCode
        0x2000,          # BaseOfData
        0x400000,        # ImageBase
        section_alignment,
        file_alignment,
        4, 0, 0, 0, 4, 0,
        0,
        size_of_image,
        size_of_headers,
        0,
        3,               # console subsystem
        0x8140,          # DllCharacteristics (dynamic base, NX)
        0x100000, 0x1000, 0x100000, 0x1000, 0,
        16,
    )
    assert len(optional) == 96, len(optional)

    data_dirs = [(0, 0)] * 16
    data_dirs[1] = import_dir  # import table
    for dir_rva, dir_size in data_dirs:
        optional += struct.pack("<II", dir_rva, dir_size)
    assert len(optional) == 0xE0

    # ---- Section headers ----
    sect_headers = b""
    for name, vsize, vaddr, rawsize, rawptr, _fill in layout:
        sect_headers += struct.pack(
            "<8sIIIIIIHHI",
            name.encode()[:8].ljust(8, b"\x00"),
            vsize, vaddr, rawsize, rawptr,
            0, 0, 0, 0,
            0x60000020 if name == ".text" else 0x40000040,
        )

    # ---- Assemble ----
    out = bytearray()
    out += dos + b"PE\x00\x00" + coff + optional + sect_headers
    out += b"\x00" * (size_of_headers - len(out))

    for i, (name, vsize, _vaddr, rawsize, _rawptr, fill) in enumerate(layout):
        if name == ".idata":
            out += idata + b"\x00" * (rawsize - len(idata))
        else:
            out += bytes([fill]) * rawsize

    out += extra
    return bytes(out)
