"""Tests for capa capability detection (MITRE ATT&CK mapping).

Unit tests mock capa output and never require the real engine. One live
test runs the real pipeline on a crafted PE but is skipped when
flare-capa is not installed.
"""

import pytest

from sleuth import capa_scan

# Capture the real lookup-independent helpers (no network involved here).
parse_attack = capa_scan._parse_attack
points_for = capa_scan._points_for


def test_parse_attack_full_form():
    a = parse_attack("Defense Evasion::Process Injection [T1055]")
    assert a == {"tactic": "Defense Evasion", "technique": "Process Injection",
                "subtechnique": "", "id": "T1055"}


def test_parse_attack_with_subtechnique():
    a = parse_attack("Collection::Input Capture::Keylogging [T1056.001]")
    assert a["tactic"] == "Collection"
    assert a["technique"] == "Input Capture"
    assert a["subtechnique"] == "Keylogging"
    assert a["id"] == "T1056.001"


def test_parse_attack_garbage_never_raises():
    a = parse_attack("not an attack string")
    assert a["id"] == ""
    a = parse_attack(None)
    assert a == {"tactic": "", "technique": "", "subtechnique": "", "id": ""}


def test_points_high_tactic():
    assert points_for([{"tactic": "Defense Evasion"}]) == 15
    assert points_for([{"tactic": "Credential Access"}]) == 15
    assert points_for([{"tactic": "Command and Control"}]) == 15


def test_points_medium_tactic():
    assert points_for([{"tactic": "Discovery"}]) == 8
    assert points_for([{"tactic": "Execution"}]) == 8


def test_points_unknown_tactic():
    assert points_for([{"tactic": "Something Else"}]) == 4
    assert points_for([]) == 4


def test_capa_signals_evidence_format():
    result = {
        "available": True,
        "capabilities": [
            {"name": "inject remote thread (process injection)",
             "namespace": "sleuth/injection",
             "attack": [{"tactic": "Defense Evasion",
                         "technique": "Process Injection",
                         "subtechnique": "", "id": "T1055"}],
             "points": 15},
        ],
    }
    signals = capa_scan.capa_signals(result)
    assert len(signals) == 1
    sig = signals[0]
    assert sig["points"] == 15
    assert "T1055" in sig["evidence"]
    assert "Process Injection" in sig["evidence"]
    assert "inject remote thread" in sig["evidence"]


def test_capa_signals_empty():
    assert capa_scan.capa_signals({"available": False, "capabilities": []}) == []
    assert capa_scan.capa_signals(None) == []


@pytest.mark.skipif(not capa_scan.CAPA_AVAILABLE,
                    reason="flare-capa not installed")
def test_scan_file_unsupported_type(tmp_path):
    p = tmp_path / "note.txt"
    p.write_bytes(b"just some text\n")
    result = capa_scan.scan_file(str(p))
    assert result["available"] is False
    assert "PE and ELF" in result["reason"]


def test_scan_file_missing_file(tmp_path):
    result = capa_scan.scan_file(str(tmp_path / "nope.bin"))
    assert result["available"] is False


def test_graceful_when_capa_missing(monkeypatch):
    monkeypatch.setattr(capa_scan, "CAPA_AVAILABLE", False)
    result = capa_scan.scan_file("/tmp/anything.exe")
    assert result["available"] is False
    assert "not installed" in result["reason"]
    assert "capa ready" not in capa_scan.status()
    assert "not installed" in capa_scan.status()


def test_status_string():
    s = capa_scan.status()
    assert isinstance(s, str) and len(s) > 0


@pytest.mark.skipif(not capa_scan.CAPA_AVAILABLE,
                    reason="flare-capa not installed")
def test_live_capa_on_crafted_pe(tmp_path):
    """End-to-end: crafted PE with injection imports matches T1055."""
    import sys
    sys.path.insert(0, str(tmp_path))  # noqa (kept simple; not needed below)
    from tests.pe_builder import build_pe

    p = tmp_path / "evil.exe"
    p.write_bytes(build_pe(
        imports={"kernel32.dll": ["CreateRemoteThread", "WriteProcessMemory"]}))
    result = capa_scan.scan_file(str(p))
    assert result["available"] is True, result.get("reason")
    names = [c["name"] for c in result["capabilities"]]
    assert any("inject remote thread" in n for n in names)
    ids = [a["id"] for c in result["capabilities"] for a in c["attack"]]
    assert "T1055" in ids
    # A clean PE with no interesting imports matches nothing.
    p2 = tmp_path / "clean.exe"
    p2.write_bytes(build_pe(imports={"kernel32.dll": ["GetTickCount"]}))
    result2 = capa_scan.scan_file(str(p2))
    assert result2["available"] is True
    assert result2["capabilities"] == []
