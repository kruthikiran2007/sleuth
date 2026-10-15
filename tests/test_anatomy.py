"""Tests for ELF/PE anatomy: real parsing plus graceful degradation."""

import sys

import pytest

from sleuth import elf_info, pe_info


def test_elf_real_binary():
    # sys.executable is an ELF on Linux; skip elsewhere.
    with open(sys.executable, "rb") as f:
        head = f.read(4)
    if head != b"\x7fELF":
        pytest.skip("not an ELF python on this platform")
    with open(sys.executable, "rb") as f:
        data = f.read()
    result = elf_info.analyze_elf(data)
    assert result["available"] is True
    assert result["sections"], "expected sections"
    assert any(s["name"] == ".text" for s in result["sections"])
    assert set(result["mitigations"]) == {"nx", "pie", "canary", "relro"}
    for s in result["sections"]:
        assert 0.0 <= s["entropy"] <= 8.0


def test_elf_garbage_degrades():
    result = elf_info.analyze_elf(b"\x7fELF" + b"\x00" * 20)
    assert result["available"] is False
    assert "reason" in result


def test_pe_garbage_degrades():
    result = pe_info.analyze_pe(b"MZ" + b"\x00" * 20)
    assert result["available"] is False
    assert "reason" in result


def _minimal_pe():
    """Build a tiny but structurally valid PE32 with one .text section."""
    import struct

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew
    pe_sig = b"PE\x00\x00"
    # COFF header: machine i386, 1 section, size of optional header
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x010F)
    # Optional header (PE32, 224 bytes): magic + zeroed, DllCharacteristics at +70
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<H", opt, 70, 0x0140)  # NX_COMPAT | DYNAMIC_BASE
    # Section header: name .text, virtual/raw sizes, raw pointer after headers
    headers_len = 64 + 4 + 20 + 0xE0 + 40
    raw_ptr = (headers_len + 511) // 512 * 512
    sec = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 512, 0x1000,
                      512, raw_ptr, 0, 0, 0, 0, 0x60000020)
    blob = bytes(dos) + pe_sig + coff + bytes(opt) + sec
    blob += b"\x00" * (raw_ptr - len(blob)) + b"\x90" * 512  # NOP sled
    return blob


def test_pe_minimal_binary():
    result = pe_info.analyze_pe(_minimal_pe())
    assert result["available"] is True
    assert result["sections"][0]["name"] == ".text"
    assert result["mitigations"]["dep"] is True
    assert result["mitigations"]["aslr"] is True
    assert isinstance(result["imports"], dict)
