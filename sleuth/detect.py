"""File-type detection using magic bytes (the first few bytes of a file).

Every file format stamps its first bytes like a wax seal. We read just those
bytes and compare them against known seals. We never run the file.
"""

import os

# Sleuth refuses to touch very large files (memory safety + sanity).
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB

# Magic byte signatures: (file_type, magic_bytes)
# Order matters: check longer/more specific signatures first.
_SIGNATURES = [
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),                       # also covers some DOS-era files
    ("macho", b"\xfe\xed\xfa\xce"),      # Mach-O 32-bit
    ("macho", b"\xfe\xed\xfa\xcf"),      # Mach-O 64-bit
    ("macho", b"\xca\xfe\xba\xbe"),      # Mach-O universal (fat) binary
    ("zip", b"PK\x03\x04"),              # ZIP — also covers APK/JAR/DOCX
    ("zip", b"PK\x05\x06"),              # empty ZIP archive
    ("zip", b"PK\x07\x08"),              # spanned ZIP archive
    ("gzip", b"\x1f\x8b"),
    ("pdf", b"%PDF"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("sqlite", b"SQLite format 3\x00"),
    ("wasm", b"\x00asm"),
    ("shebang", b"#!"),                  # script: #!/bin/bash, #!/usr/bin/env python ...
]

# Signatures that only match at a non-zero offset: (file_type, offset, magic)
_OFFSET_SIGNATURES = [
    ("elf", 0, b"\x7fELF"),  # kept for symmetry; real offset sigs below
]

# ZIP-based formats we can tell apart by inner file names (checked lazily).
_ZIP_FLAVORS = {
    "AndroidManifest.xml": "apk",
    "META-INF/": "jar",  # generic Java archive marker
    "word/": "docx",
}


def check_size_ok(path):
    """Return (ok, size_bytes). Sleuth refuses files over MAX_FILE_SIZE."""
    size = os.path.getsize(path)
    return size <= MAX_FILE_SIZE, size


def detect_type(path):
    """Detect the file type of *path* from its magic bytes.

    Returns one of: 'elf', 'pe', 'macho', 'apk', 'zip', 'jar', 'docx',
    'gzip', 'pdf', 'png', 'sqlite', 'wasm', 'script', 'text', 'unknown'.

    Only the first 8 bytes are read (plus a small peek for ZIP flavors).
    """
    with open(path, "rb") as f:
        head = f.read(8)

    for ftype, magic in _SIGNATURES:
        if head.startswith(magic):
            if ftype == "zip":
                return _zip_flavor(path)
            if ftype == "shebang":
                return "script"
            return ftype

    # Not a known binary: is it plain human-readable text?
    if _looks_like_text(path):
        return "text"

    return "unknown"


def _zip_flavor(path):
    """Peek inside a ZIP to distinguish APK / JAR / DOCX from plain ZIP."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
        text = chunk.decode("utf-8", errors="ignore")
        for marker, flavor in _ZIP_FLAVORS.items():
            if marker in text:
                return flavor
    except OSError:
        pass
    return "zip"


def _looks_like_text(path, sample_size=4096):
    """Heuristic: file is text if a sample has no NUL bytes and is mostly printable."""
    try:
        with open(path, "rb") as f:
            sample = f.read(sample_size)
    except OSError:
        return False
    if not sample:
        return True  # empty file counts as text
    if b"\x00" in sample:
        return False
    # Count bytes that are printable ASCII, tab, newline, carriage return.
    printable = sum(
        1 for b in sample if b in b"\t\n\r" or 32 <= b < 127
    )
    return printable / len(sample) > 0.95
