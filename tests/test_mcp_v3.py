"""Tests for the v0.3 MCP tools: capa_scan, threat_intel, diff_binaries,
disassemble."""

import json

import pytest

from sleuth import capa_scan, mcp_server
from tests.pe_builder import build_pe


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


@pytest.mark.skipif(not capa_scan.CAPA_AVAILABLE,
                    reason="flare-capa not installed")
def test_tool_capa_scan_pe(tmp_path):
    p = _write(tmp_path, "evil.exe", build_pe(
        imports={"kernel32.dll": ["CreateRemoteThread", "WriteProcessMemory"]}))
    result = mcp_server.tool_capa_scan(p)
    assert result["ok"] is True
    assert result["available"] is True
    ids = [a["id"] for c in result["capabilities"] for a in c["attack"]]
    assert "T1055" in ids
    json.dumps(result)


def test_tool_capa_scan_text_graceful(tmp_path):
    p = _write(tmp_path, "note.txt", b"hello\n")
    result = mcp_server.tool_capa_scan(p)
    assert result["ok"] is True
    assert result["available"] is False


def test_tool_threat_intel_offline(tmp_path):
    # conftest stubs lookup offline
    p = _write(tmp_path, "a.bin", b"hello\n")
    result = mcp_server.tool_threat_intel(p)
    assert result["ok"] is True
    assert result["available"] is False
    assert result["known"] is False
    json.dumps(result)


def test_tool_diff_binaries(tmp_path):
    old = _write(tmp_path, "old.exe",
                 build_pe(imports={"kernel32.dll": ["GetTickCount"]}))
    new = _write(tmp_path, "new.exe", build_pe(
        imports={"kernel32.dll": ["GetTickCount", "CreateRemoteThread"]}))
    result = mcp_server.tool_diff_binaries(old, new)
    assert result["ok"] is True
    assert "CreateRemoteThread" in result["diff"]["imports_added"]
    json.dumps(result)


def test_tool_diff_binaries_missing_file(tmp_path):
    result = mcp_server.tool_diff_binaries("/no/old.exe", "/no/new.exe")
    assert result["ok"] is False


def test_tool_disassemble(tmp_path):
    p = _write(tmp_path, "t.exe", build_pe())
    result = mcp_server.tool_disassemble(p, count=4)
    assert result["ok"] is True
    assert result["available"] is True
    assert result["arch"] == "x86-32"
    assert len(result["instructions"]) == 4
    json.dumps(result)


def test_tool_disassemble_unsupported(tmp_path):
    p = _write(tmp_path, "note.txt", b"hello\n")
    result = mcp_server.tool_disassemble(p)
    assert result["ok"] is True
    assert result["available"] is False


def test_nine_tools_registered():
    names = [name for name, _ in mcp_server._TOOL_REGISTRATIONS]
    assert names == ["analyze_file", "get_strings", "scan_secrets",
                     "yara_scan", "apk_info", "capa_scan", "threat_intel",
                     "diff_binaries", "disassemble"]
