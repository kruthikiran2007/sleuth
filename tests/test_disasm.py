"""Tests for entry-point disassembly (capstone)."""

import pytest

from sleuth import disasm
from tests.pe_builder import build_pe


def test_disassemble_known_bytes():
    # push rbp; mov rbp, rsp; xor eax, eax; syscall; ret
    code = bytes.fromhex("554889e531c00f05c3")
    insns = disasm.disassemble_bytes(code, "x86", 64, base_addr=0x1000,
                                     count=10)
    mnems = [i["mnemonic"] for i in insns]
    assert mnems == ["push", "mov", "xor", "syscall", "ret"]
    assert insns[0]["address"] == "0x1000"
    assert insns[0]["op_str"] == "rbp"
    assert insns[2]["op_str"] == "eax, eax"


def test_disassemble_respects_count():
    code = b"\x90" * 64  # nops
    insns = disasm.disassemble_bytes(code, "x86", 64, count=5)
    assert len(insns) == 5
    assert all(i["mnemonic"] == "nop" for i in insns)


def test_disassemble_32bit():
    # push ebp; mov ebp, esp
    code = bytes.fromhex("5589e5")
    insns = disasm.disassemble_bytes(code, "x86", 32, count=4)
    assert [i["mnemonic"] for i in insns] == ["push", "mov"]


def test_weak_signal_syscall():
    code = bytes.fromhex("554889e50f05c3")
    insns = disasm.disassemble_bytes(code, "x86", 64, count=10)
    signals = disasm._weak_signals(insns)
    assert len(signals) == 1
    assert signals[0]["points"] == 3
    assert "syscall" in signals[0]["evidence"]
    assert "weak" in signals[0]["detail"].lower()


def test_weak_signal_fnstenv():
    code = bytes.fromhex("d9e8d97424f4")  # fld1; fnstenv [esp-0xc]
    insns = disasm.disassemble_bytes(code, "x86", 32, count=10)
    signals = disasm._weak_signals(insns)
    assert any("fnstenv" in s["evidence"] for s in signals)


def test_weak_signal_heavy_xor():
    code = bytes.fromhex("31c0") * 8  # 8x xor eax, eax
    insns = disasm.disassemble_bytes(code, "x86", 32, count=16)
    signals = disasm._weak_signals(insns)
    assert any("XOR" in s["evidence"] for s in signals)


def test_no_weak_signals_for_benign():
    code = bytes.fromhex("554889e5c9c3")  # push/mov/leave/ret
    insns = disasm.disassemble_bytes(code, "x86", 32, count=10)
    assert disasm._weak_signals(insns) == []


def test_disassemble_file_pe_entry(tmp_path):
    p = tmp_path / "t.exe"
    p.write_bytes(build_pe())
    result = disasm.disassemble_file(str(p), "pe", count=8)
    assert result["available"] is True
    assert result["arch"] == "x86-32"
    assert result["count"] == 8
    # .text is filled with 0xCC -> int3
    assert result["instructions"][0]["mnemonic"] == "int3"
    assert result["instructions"][0]["address"] == "0x401000"


def test_disassemble_file_unsupported_type(tmp_path):
    p = tmp_path / "note.txt"
    p.write_bytes(b"hello\n")
    result = disasm.disassemble_file(str(p), "text")
    assert result["available"] is False
    assert "PE and ELF" in result["reason"]


def test_disassemble_file_missing(tmp_path):
    result = disasm.disassemble_file(str(tmp_path / "nope.exe"), "pe")
    assert result["available"] is False


def test_graceful_when_capstone_missing(monkeypatch):
    monkeypatch.setattr(disasm, "CAPSTONE_AVAILABLE", False)
    result = disasm.disassemble_file("/tmp/anything.exe", "pe")
    assert result["available"] is False
    assert "capstone" in result["reason"]
    with pytest.raises(RuntimeError):
        disasm.disassemble_bytes(b"\x90", "x86", 64)


def test_disassemble_file_elf_entry():
    # Regression: pyelftools>=0.30 returns e_machine as the string
    # 'EM_X86_64', which missed the int-keyed _ELF_MACHINES lookup and made
    # disassemble_file report every x86-64 ELF as "unsupported architecture".
    import shutil

    true_bin = shutil.which("true")
    if not true_bin:
        pytest.skip("no 'true' binary on this platform")
    result = disasm.disassemble_file(true_bin, "elf", count=8)
    assert result["available"] is True
    assert result["arch"] == "x86-64"
    assert result["count"] >= 1
    assert result["instructions"][0]["mnemonic"]


def test_elf_arch_accepts_int_and_string():
    assert disasm._elf_arch(62) == ("x86", 64)
    assert disasm._elf_arch(3) == ("x86", 32)
    assert disasm._elf_arch("EM_X86_64") == ("x86", 64)
    assert disasm._elf_arch("EM_386") == ("x86", 32)
    assert disasm._elf_arch("EM_ARM") is None
    assert disasm._elf_arch(40) is None
