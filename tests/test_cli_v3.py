"""Tests for the v0.3 CLI commands: capa, intel, diff, disasm."""

import json

import pytest

from sleuth import capa_scan, cli
from tests.pe_builder import build_pe


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _evil_pe():
    return build_pe(
        imports={"kernel32.dll": ["CreateRemoteThread", "WriteProcessMemory",
                                  "VirtualAlloc"]})


@pytest.mark.skipif(not capa_scan.CAPA_AVAILABLE,
                    reason="flare-capa not installed")
def test_capa_command_on_pe(tmp_path, capsys):
    p = _write(tmp_path, "evil.exe", _evil_pe())
    assert cli.main(["capa", p]) == 0
    out = capsys.readouterr().out
    assert "capa ready" in out
    assert "T1055" in out


def test_capa_command_on_text(tmp_path, capsys):
    p = _write(tmp_path, "note.txt", b"hello\n")
    assert cli.main(["capa", p]) == 0
    out = capsys.readouterr().out
    assert "unavailable" in out.lower()


def test_intel_command_offline(tmp_path, capsys):
    # conftest stubs the lookup offline; command must still exit 0.
    p = _write(tmp_path, "a.bin", b"hello\n")
    assert cli.main(["intel", p]) == 0
    out = capsys.readouterr().out
    assert "sha256:" in out
    assert "unavailable" in out.lower()


def test_diff_command(tmp_path, capsys):
    old = _write(tmp_path, "old.exe",
                 build_pe(imports={"kernel32.dll": ["GetTickCount"]}))
    new = _write(tmp_path, "new.exe", _evil_pe())
    assert cli.main(["diff", old, new]) == 0
    out = capsys.readouterr().out
    assert "Sleuth diff" in out
    assert "CreateRemoteThread" in out


def test_diff_command_json(tmp_path, capsys):
    old = _write(tmp_path, "old.exe",
                 build_pe(imports={"kernel32.dll": ["GetTickCount"]}))
    new = _write(tmp_path, "new.exe", _evil_pe())
    assert cli.main(["diff", old, new, "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert "CreateRemoteThread" in d["imports_added"]
    assert "summary" in d


def test_diff_command_html(tmp_path, capsys):
    old = _write(tmp_path, "old.exe",
                 build_pe(imports={"kernel32.dll": ["GetTickCount"]}))
    new = _write(tmp_path, "new.exe", _evil_pe())
    html_path = str(tmp_path / "diff.html")
    assert cli.main(["diff", old, new, "--html", html_path]) == 0
    content = (tmp_path / "diff.html").read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")
    assert "CreateRemoteThread" in content


def test_diff_command_missing_file(capsys):
    assert cli.main(["diff", "/no/old.exe", "/no/new.exe"]) == 1


def test_disasm_command(tmp_path, capsys):
    p = _write(tmp_path, "t.exe", build_pe())
    assert cli.main(["disasm", p, "--count", "4"]) == 0
    out = capsys.readouterr().out
    assert "x86-32" in out
    assert "int3" in out


def test_analyze_no_intel_flag(tmp_path, capsys):
    p = _write(tmp_path, "note.txt", b"hello\n")
    assert cli.main(["analyze", p, "--no-intel"]) == 0
    out = capsys.readouterr().out
    assert "VERDICT: CLEAN" in out
    assert "skipped (--no-intel)" in out


def test_analyze_disasm_flag(tmp_path, capsys):
    p = _write(tmp_path, "t.exe", build_pe())
    assert cli.main(["analyze", p, "--disasm"]) == 0
    out = capsys.readouterr().out
    assert "Disassembly excerpt" in out


@pytest.mark.skipif(not capa_scan.CAPA_AVAILABLE,
                    reason="flare-capa not installed")
def test_analyze_evil_pe_includes_capa_and_verdict(tmp_path, capsys):
    p = _write(tmp_path, "evil.exe", _evil_pe())
    assert cli.main(["analyze", p]) == 0
    out = capsys.readouterr().out
    assert "capa capabilities" in out
    assert "T1055" in out
    # injection chain (30) + capa (15) + imports -> MALICIOUS-LOOKING
    assert "MALICIOUS-LOOKING" in out
