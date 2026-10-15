"""Tests for sleuth.yara_scan (Feature 1: YARA rules engine).

Never executes any target: all scan inputs are plain crafted byte strings.
Compile-dependent tests are skipped when yara-python is unavailable.
"""

import pytest

from sleuth import yara_scan
from sleuth.yara_scan import (
    YARA_AVAILABLE,
    RULES_DIR,
    status,
    load_rules,
    scan_data,
    scan_file,
    yara_signals,
)

needs_yara = pytest.mark.skipif(
    not YARA_AVAILABLE, reason="yara-python not installed"
)

# Crafted marker bytes — generic signature strings only, no live code.
PACKED_BYTES = b"MZ\x90\x00" + b"\x00" * 64 + b"UPX!"
RANSOM_BYTES = b"YOUR FILES HAVE BEEN ENCRYPTED" + b"\x00" * 8 + b"pay via .onion and bitcoin"
SHELL_BYTES = b"/bin/sh\x00socket\x00connect\x00"
PS_BYTES = b"powershell -EncodedCommand aGVsbG8="
HACKTOOL_BYTES = b"pwdump and psexec utilities"
CLEAN_BYTES = b"hello world"


@needs_yara
def test_load_rules_compiles_starter_ruleset():
    rules = load_rules()
    assert rules is not None


@needs_yara
def test_load_rules_is_cached():
    assert load_rules() is load_rules()


@needs_yara
def test_load_rules_missing_dir_returns_none():
    assert load_rules("/nonexistent/rules-dir") is None


@needs_yara
def test_scan_data_positive_upx():
    hits = scan_data(PACKED_BYTES)
    names = [h["rule"] for h in hits]
    assert "upx_packer" in names
    hit = next(h for h in hits if h["rule"] == "upx_packer")
    assert hit["severity"] == "medium"
    assert hit["matches"]
    m = hit["matches"][0]
    assert isinstance(m["name"], str) and "$" in m["name"]
    assert isinstance(m["offset"], int) and m["offset"] >= 0
    assert "UPX!" in m["preview"]


@needs_yara
def test_scan_data_positive_ransomware_combo():
    hits = scan_data(RANSOM_BYTES)
    names = [h["rule"] for h in hits]
    assert "ransomware_keywords" in names
    hit = next(h for h in hits if h["rule"] == "ransomware_keywords")
    assert hit["severity"] == "high"


@needs_yara
def test_scan_data_positive_shell_powershell_hacktool():
    assert "reverse_shell_patterns" in [h["rule"] for h in scan_data(SHELL_BYTES)]
    assert "suspicious_powershell" in [h["rule"] for h in scan_data(PS_BYTES)]
    assert "hacktool_strings" in [h["rule"] for h in scan_data(HACKTOOL_BYTES)]


@needs_yara
def test_scan_data_negative_clean_bytes():
    assert scan_data(CLEAN_BYTES) == []


@needs_yara
def test_scan_data_bad_input_returns_empty():
    assert scan_data(None) == []
    assert scan_data("not bytes") == []


@needs_yara
def test_scan_file_reads_and_matches(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(PACKED_BYTES + b"\x00" * 16 + RANSOM_BYTES)
    rules_hit = [h["rule"] for h in scan_file(str(p))]
    assert "upx_packer" in rules_hit
    assert "ransomware_keywords" in rules_hit


@needs_yara
def test_scan_file_missing_returns_empty():
    assert scan_file("/nonexistent/file.bin") == []


@needs_yara
def test_preview_truncation_and_decoding():
    # Long matched string -> preview truncated to 60 chars; undecodable
    # bytes decode with errors="replace".
    long_note = b"YOUR FILES HAVE BEEN ENCRYPTED" + b"\x00" * 200
    hits = scan_data(long_note)
    hit = next(h for h in hits if h["rule"] == "ransomware_keywords")
    for m in hit["matches"]:
        assert len(m["preview"]) <= 60
        m["preview"].encode("utf-8")  # valid str, decode never raised


@needs_yara
def test_yara_signals_point_values():
    sample = [
        {"rule": "a", "tags": [], "severity": "high", "matches": []},
        {"rule": "b", "tags": [], "severity": "medium", "matches": []},
        {"rule": "c", "tags": [], "severity": "low", "matches": []},
        {"rule": "d", "tags": [], "severity": "weird", "matches": []},
    ]
    signals = yara_signals(sample)
    assert [s["points"] for s in signals] == [20, 10, 5, 10]
    for s in signals:
        assert "evidence" in s and "detail" in s


@needs_yara
def test_yara_signals_evidence_cites_rule_and_identifier():
    hits = scan_data(PACKED_BYTES)
    signals = yara_signals(hits)
    upx = next(s for s in signals if "upx_packer" in s["evidence"])
    assert "$" in upx["evidence"]  # string identifier present
    assert isinstance(upx["detail"], str)


@needs_yara
def test_status_ready_mentions_rules_compiled():
    assert "yara ready" in status()
    assert "rules compiled" in status()


def test_graceful_degradation_without_yara(monkeypatch):
    # Simulate yara-python missing: scan returns [], status points at pip.
    monkeypatch.setattr(yara_scan, "yara", None)
    monkeypatch.setattr(yara_scan, "YARA_AVAILABLE", False)
    assert scan_data(b"UPX!") == []
    assert scan_data(RANSOM_BYTES) == []
    assert "pip install yara-python" in status()
    assert load_rules() is None


def test_yara_signals_handles_empty():
    assert yara_signals([]) == []
    assert yara_signals(None) == []
