"""Tests for the heuristics/verdict engine."""

from sleuth import heuristics


def _anatomy(**over):
    base = {"sections": [], "imports": [], "mitigations": {}}
    base.update(over)
    return base


def test_clean_when_no_signals():
    result = heuristics.evaluate(_anatomy(), [], {"ips": [], "urls": []}, "text")
    assert result["verdict"] == "CLEAN"
    assert result["score"] == 0
    assert result["signals"] == []


def test_high_entropy_section_flagged():
    anatomy = _anatomy(sections=[{"name": ".packed", "size": 1000, "entropy": 7.9}])
    result = heuristics.evaluate(anatomy, [], {"ips": [], "urls": []}, "elf")
    assert any("entropy" in s["evidence"] for s in result["signals"])
    assert result["score"] >= 15


def test_entropy_below_threshold_ignored():
    anatomy = _anatomy(sections=[{"name": ".text", "size": 1000, "entropy": 5.0}])
    result = heuristics.evaluate(anatomy, [], {"ips": [], "urls": []}, "elf")
    assert result["signals"] == []


def test_injection_chain_scores_malicious_looking():
    imports = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
               "ptrace", "URLDownloadToFile"]
    result = heuristics.evaluate(
        _anatomy(imports=imports), [], {"ips": [], "urls": []}, "pe")
    assert result["verdict"] == "MALICIOUS-LOOKING"
    assert result["score"] >= 60
    # The combo signal must cite all three imports as evidence.
    combo = [s for s in result["signals"] if "process-injection" in s["detail"]]
    assert combo
    assert "CreateRemoteThread" in combo[0]["evidence"]


def test_suspicious_single_import():
    result = heuristics.evaluate(
        _anatomy(imports=["ptrace"]), [], {"ips": [], "urls": []}, "elf")
    assert result["verdict"] == "CLEAN"  # 15 pts alone is below SUSPICIOUS
    assert any(s["evidence"] == "import 'ptrace'" for s in result["signals"])


def test_missing_mitigations_add_weak_signals():
    anatomy = _anatomy(mitigations={"nx": False, "pie": True})
    result = heuristics.evaluate(anatomy, [], {"ips": [], "urls": []}, "elf")
    assert any("nx" in s["evidence"] for s in result["signals"])
    assert not any("pie" in s["evidence"] for s in result["signals"])


def test_embedded_secret_is_signal_with_redacted_preview():
    secrets = [{"type": "aws_access_key", "preview": "AKIA...", "line": 3}]
    result = heuristics.evaluate(_anatomy(), secrets, {"ips": [], "urls": []}, "elf")
    assert any(s["evidence"].startswith("secret type 'aws_access_key'")
               for s in result["signals"])
    for s in result["signals"]:
        assert "AKIAIOSFODNN7EXAMPLE" not in s["evidence"]


def test_every_signal_cites_evidence():
    anatomy = _anatomy(
        sections=[{"name": ".x", "size": 500, "entropy": 7.8}],
        imports=["ptrace"],
        mitigations={"canary": False},
    )
    secrets = [{"type": "github_token", "preview": "ghp_...", "line": 1}]
    indicators = {"ips": ["1.2.3.4"], "urls": ["http://evil.example/"]}
    result = heuristics.evaluate(anatomy, secrets, indicators, "elf")
    assert result["signals"], "expected signals"
    for s in result["signals"]:
        assert s["evidence"], "signal without evidence: %r" % s
        assert s["points"] > 0


def test_verdict_bands():
    low = heuristics.evaluate(_anatomy(), [], {"ips": ["9.9.9.9"], "urls": []}, "elf")
    assert low["verdict"] == "CLEAN"  # a lone IP (2 pts) stays CLEAN
    mid = heuristics.evaluate(
        _anatomy(imports=["ptrace", "memfd_create"]), [], {"ips": [], "urls": []}, "elf")
    assert mid["verdict"] == "SUSPICIOUS"  # 30 pts


def test_unconfirmed_string_hit_is_weaker():
    # Same API name, but only seen as text (unparseable binary): weaker signal,
    # honestly labeled as unconfirmed.
    result = heuristics.evaluate(
        _anatomy(), [], {"ips": [], "urls": []}, "unknown",
        strings=["CreateRemoteThread"])
    hits = [s for s in result["signals"] if "CreateRemoteThread" in s["evidence"]]
    assert hits
    assert "unconfirmed" in hits[0]["evidence"]
    assert hits[0]["points"] < 20  # weaker than the confirmed-import score


def test_confirmed_import_not_double_counted():
    result = heuristics.evaluate(
        _anatomy(imports=["ptrace"]), [], {"ips": [], "urls": []}, "elf",
        strings=["ptrace"])
    ptrace_hits = [s for s in result["signals"] if "ptrace" in s["evidence"]]
    assert len(ptrace_hits) == 1  # confirmed import only, no duplicate
