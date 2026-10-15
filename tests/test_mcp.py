"""Tests for sleuth.mcp_server (Feature 3: MCP server).

The five plain tool functions are tested directly (no MCP server needed).
Server construction is tested only when the ``mcp`` package is installed;
the missing-mcp path is tested via monkeypatching.
"""

import asyncio
import json

import pytest

import sleuth.detect
import sleuth.mcp_server as mcp_server
from sleuth.mcp_server import (
    MCP_AVAILABLE,
    build_server,
    tool_analyze_file,
    tool_apk_info,
    tool_get_strings,
    tool_scan_secrets,
    tool_yara_scan,
)

EXPECTED_TOOL_NAMES = [
    "analyze_file",
    "get_strings",
    "scan_secrets",
    "yara_scan",
    "apk_info",
    "capa_scan",
    "threat_intel",
    "diff_binaries",
    "disassemble",
]


@pytest.fixture
def text_file(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_text(
        "hello sleuth\n"
        "visit https://example.com/report for details\n"
        "token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    )
    return str(p)


@pytest.fixture
def big_file(tmp_path):
    p = tmp_path / "big.txt"
    p.write_bytes(b"0123456789abcdef")  # 16 bytes
    return str(p)


# ---- happy path: each tool on a small text file ----------------------------


def _assert_ok_json(result):
    assert isinstance(result, dict)
    assert result.get("ok") is True
    json.dumps(result)  # must be JSON-serializable


def test_tool_analyze_file(text_file):
    result = tool_analyze_file(text_file)
    _assert_ok_json(result)
    report = result["report"]
    assert report["file_type"] == "text"
    assert "verdict" in report


def test_tool_get_strings(text_file):
    result = tool_get_strings(text_file)
    _assert_ok_json(result)
    assert isinstance(result["strings"], list)
    assert any("hello sleuth" in s for s in result["strings"])
    assert result["truncated"] is False


def test_tool_get_strings_truncation(text_file):
    result = tool_get_strings(text_file, limit=1)
    _assert_ok_json(result)
    assert len(result["strings"]) == 1
    assert result["truncated"] is True


def test_tool_scan_secrets(text_file):
    result = tool_scan_secrets(text_file)
    _assert_ok_json(result)
    assert isinstance(result["findings"], list)
    # ghp_ token should be found; preview must be redacted, never the secret
    ghp = [f for f in result["findings"] if "ghp_" in f["preview"] or f["type"]]
    assert ghp, "expected at least one secret finding"
    for f in ghp:
        assert f["preview"].endswith("...") or f["preview"] == "****"
        assert "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in f["preview"]


def test_tool_yara_scan(text_file):
    result = tool_yara_scan(text_file)
    _assert_ok_json(result)
    assert "available" in result
    assert isinstance(result["matches"], list)


def test_tool_apk_info(text_file):
    result = tool_apk_info(text_file)
    _assert_ok_json(result)
    assert isinstance(result["apk"], dict)
    # a plain text file is not an APK
    assert result["apk"].get("available") is False


# ---- missing file: ok False, "error" key, no exception ---------------------


@pytest.mark.parametrize(
    "fn",
    [
        tool_analyze_file,
        tool_get_strings,
        tool_scan_secrets,
        tool_yara_scan,
        tool_apk_info,
    ],
)
def test_missing_file_returns_error_dict(fn):
    result = fn("/nonexistent/path/nope.bin")
    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert "error" in result and result["error"]


# ---- oversize gate ----------------------------------------------------------


@pytest.mark.parametrize(
    "fn",
    [
        tool_analyze_file,
        tool_get_strings,
        tool_scan_secrets,
        tool_yara_scan,
        tool_apk_info,
    ],
)
def test_oversize_gate_refuses(fn, big_file, monkeypatch):
    monkeypatch.setattr(sleuth.detect, "MAX_FILE_SIZE", 10)  # 16-byte file now "huge"
    result = fn(big_file)
    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert "error" in result
    assert "limit" in result["error"]


# ---- mcp-absent path --------------------------------------------------------


def test_build_server_raises_without_mcp(monkeypatch):
    monkeypatch.setattr(mcp_server, "FastMCP", None)
    monkeypatch.setattr(mcp_server, "MCP_AVAILABLE", False)
    with pytest.raises(RuntimeError) as excinfo:
        build_server()
    assert "pip install" in str(excinfo.value)


def test_tools_importable_without_mcp(monkeypatch, text_file):
    # Plain tool functions must not reference FastMCP at all.
    monkeypatch.setattr(mcp_server, "FastMCP", None)
    monkeypatch.setattr(mcp_server, "MCP_AVAILABLE", False)
    result = tool_analyze_file(text_file)
    assert result.get("ok") is True


# ---- server construction (only when mcp is installed) -----------------------


@pytest.mark.skipif(not MCP_AVAILABLE, reason="mcp package not installed")
def test_build_server_registers_all_nine_tools():
    server = build_server()
    names = [t.name for t in asyncio.run(server.list_tools())]
    assert sorted(names) == sorted(EXPECTED_TOOL_NAMES)
