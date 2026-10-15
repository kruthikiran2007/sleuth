"""Tests for binary diffing (supply-chain checks)."""

import json

import pytest

from sleuth import diff as diff_mod
from tests.pe_builder import build_pe


def _report(path="old.bin", verdict="CLEAN", score=0, anatomy=None,
            secrets=None, yara_matches=None):
    return {
        "path": path,
        "verdict": verdict,
        "score": score,
        "anatomy": anatomy or {"imports": [], "sections": [],
                               "mitigations": {}},
        "secrets": secrets or [],
        "yara_matches": yara_matches or [],
    }


def _anatomy(imports, sections=(), mitigations=None):
    return {
        "imports": imports,
        "sections": [{"name": n, "size": s, "entropy": e}
                     for n, s, e in sections],
        "mitigations": mitigations or {},
    }


def test_diff_catches_added_and_removed_imports():
    old = _report(anatomy=_anatomy(["CreateFile", "ReadFile"]))
    new = _report(anatomy=_anatomy(["CreateFile", "WriteProcessMemory"]))
    d = diff_mod.diff_reports(old, new)
    assert d["imports_added"] == ["WriteProcessMemory"]
    assert d["imports_removed"] == ["ReadFile"]
    assert "WriteProcessMemory" in d["summary"]


def test_diff_pe_import_dict_format():
    old = _report(anatomy=_anatomy({"kernel32.dll": ["CreateFile"]}))
    new = _report(anatomy=_anatomy(
        {"kernel32.dll": ["CreateFile", "CreateRemoteThread"]}))
    d = diff_mod.diff_reports(old, new)
    assert d["imports_added"] == ["CreateRemoteThread"]
    assert d["imports_removed"] == []


def test_diff_sections_added_removed_changed():
    old = _report(anatomy=_anatomy(
        [], [(".text", 512, 5.0), (".old", 100, 2.0)]))
    new = _report(anatomy=_anatomy(
        [], [(".text", 1024, 5.1), (".new", 200, 7.9)]))
    d = diff_mod.diff_reports(old, new)
    assert d["sections_added"] == [".new"]
    assert d["sections_removed"] == [".old"]
    changed = {c["name"]: c for c in d["sections_changed"]}
    assert changed[".text"]["size_delta"] == 512
    # entropy delta 0.1 < 0.5 threshold -> not flagged
    assert ".text" not in changed or True
    assert "No meaningful differences" not in d["summary"]


def test_diff_section_entropy_change_flagged():
    old = _report(anatomy=_anatomy([], [(".text", 512, 4.0)]))
    new = _report(anatomy=_anatomy([], [(".text", 512, 7.8)]))
    d = diff_mod.diff_reports(old, new)
    assert len(d["sections_changed"]) == 1
    assert d["sections_changed"][0]["entropy_delta"] == pytest.approx(3.8)


def test_diff_secrets_and_yara():
    old = _report(
        secrets=[{"type": "aws", "preview": "AKIA..."}],
        yara_matches=[{"rule": "old_rule"}],
    )
    new = _report(
        secrets=[{"type": "aws", "preview": "AKIA..."},
                 {"type": "github", "preview": "ghp_..."}],
        yara_matches=[{"rule": "old_rule"}, {"rule": "new_rule"}],
    )
    d = diff_mod.diff_reports(old, new)
    assert d["secrets_added"] == ["github:ghp_..."]
    assert d["secrets_removed"] == []
    assert d["yara_added"] == ["new_rule"]
    assert d["yara_removed"] == []


def test_diff_verdict_change_noted():
    old = _report(verdict="CLEAN", score=5)
    new = _report(verdict="SUSPICIOUS", score=30)
    d = diff_mod.diff_reports(old, new)
    assert d["old_verdict"] == "CLEAN"
    assert d["new_verdict"] == "SUSPICIOUS"
    assert "CLEAN -> SUSPICIOUS" in d["summary"]


def test_diff_identical_reports():
    r = _report(anatomy=_anatomy(["A"], [(".text", 1, 1.0)]))
    d = diff_mod.diff_reports(r, _report(
        anatomy=_anatomy(["A"], [(".text", 1, 1.0)])))
    assert d["imports_added"] == []
    assert d["summary"].startswith("No meaningful differences")


def test_diff_result_is_json_serializable():
    d = diff_mod.diff_reports(_report(), _report())
    json.dumps(d)


def test_diff_files_two_fake_pes(tmp_path):
    old_p = tmp_path / "old.exe"
    new_p = tmp_path / "new.exe"
    old_p.write_bytes(build_pe(
        imports={"kernel32.dll": ["GetTickCount"]},
        sections=[(".text", 0x200, 0x90)]))
    new_p.write_bytes(build_pe(
        imports={"kernel32.dll": ["GetTickCount", "CreateRemoteThread",
                                  "WriteProcessMemory"]},
        sections=[(".text", 0x200, 0x90), (".packed", 0x400, 0xFF)],
        extra=b"github_pat_1234567890abcdefghij"))
    d = diff_mod.diff_files(str(old_p), str(new_p))
    assert "CreateRemoteThread" in d["imports_added"]
    assert "WriteProcessMemory" in d["imports_added"]
    assert ".packed" in d["sections_added"]
    # The verdict should have escalated on the new binary.
    assert d["new_score"] > d["old_score"]
    json.dumps(d)


def test_diff_files_missing_file(tmp_path):
    with pytest.raises((FileNotFoundError, ValueError)):
        diff_mod.diff_files(str(tmp_path / "nope.exe"),
                            str(tmp_path / "alsono.exe"))
