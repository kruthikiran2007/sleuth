"""Tests for v0.3 HTML rendering: capa, threat intel, disassembly, diff."""

from sleuth import report_html


def _base_report(**over):
    r = {
        "path": "/tmp/x.exe",
        "size": 100,
        "file_type": "pe",
        "string_count": 5,
        "verdict": "SUSPICIOUS",
        "score": 30,
        "signals": [],
        "secrets": [],
        "indicators": {"ips": [], "urls": []},
        "anatomy": {"available": False, "reason": "n/a"},
        "yara_matches": [],
        "apk": None,
    }
    r.update(over)
    return r


def test_html_capa_section():
    r = _base_report(capa={
        "available": True,
        "capabilities": [
            {"name": "inject remote thread (process injection)",
             "namespace": "sleuth/injection",
             "attack": [{"tactic": "Defense Evasion",
                         "technique": "Process Injection",
                         "subtechnique": "", "id": "T1055"}],
             "points": 15},
        ],
    })
    html = report_html.render_html(r)
    assert "capa capabilities" in html
    assert "T1055" in html
    assert "Process Injection" in html


def test_html_capa_unavailable_reason():
    r = _base_report(capa={"available": False,
                           "reason": "capa supports PE and ELF targets only"})
    html = report_html.render_html(r)
    assert "capa supports PE and ELF" in html


def test_html_intel_known():
    r = _base_report(intel={
        "available": True, "known": True, "sha256": "ab" * 32,
        "family": "Emotet", "tags": ["trojan"], "first_seen": "2024-01-01",
        "reporter": "abuse_ch",
    })
    html = report_html.render_html(r)
    assert "KNOWN MALWARE" in html
    assert "Emotet" in html


def test_html_intel_unknown():
    r = _base_report(intel={"available": True, "known": False,
                            "sha256": "cd" * 32})
    html = report_html.render_html(r)
    assert "unknown sample" in html.lower()


def test_html_disasm_excerpt():
    r = _base_report(disasm={
        "available": True, "arch": "x86-64", "count": 2,
        "instructions": [
            {"address": "0x1000", "mnemonic": "push", "op_str": "rbp"},
            {"address": "0x1001", "mnemonic": "ret", "op_str": ""},
        ],
        "weak_signals": [],
    })
    html = report_html.render_html(r)
    assert "Disassembly excerpt" in html
    assert "0x1000" in html
    assert "push" in html


def test_html_escapes_capa_content():
    r = _base_report(capa={
        "available": True,
        "capabilities": [
            {"name": "<script>alert(1)</script>", "namespace": "",
             "attack": [], "points": 4},
        ],
    })
    html = report_html.render_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def _diff():
    return {
        "old_path": "old.exe", "new_path": "new.exe",
        "old_verdict": "CLEAN", "new_verdict": "SUSPICIOUS",
        "old_score": 5, "new_score": 30,
        "imports_added": ["CreateRemoteThread"],
        "imports_removed": [],
        "sections_added": [".packed"],
        "sections_removed": [],
        "sections_changed": [{"name": ".text", "size_delta": 512,
                              "entropy_delta": 3.8}],
        "secrets_added": ["github:ghp_..."],
        "secrets_removed": [],
        "yara_added": ["upx_packer"],
        "yara_removed": [],
        "mitigations_changed": {"aslr": {"old": True, "new": False}},
        "summary": "Differences: 1 import(s) added (CreateRemoteThread).",
    }


def test_render_diff_html(tmp_path):
    html = report_html.render_diff_html(_diff())
    assert html.startswith("<!DOCTYPE html>")
    assert "CreateRemoteThread" in html
    assert ".packed" in html
    assert "upx_packer" in html
    assert "CLEAN" in html and "SUSPICIOUS" in html


def test_write_diff_html(tmp_path):
    out = str(tmp_path / "d.html")
    assert report_html.write_diff_html(_diff(), out) == out
    content = (tmp_path / "d.html").read_text(encoding="utf-8")
    assert "Sleuth diff" in content


def test_diff_html_escapes_content():
    d = _diff()
    d["imports_added"] = ["<img src=x onerror=alert(1)>"]
    html = report_html.render_diff_html(d)
    assert "<img src=x" not in html
    assert "&lt;img" in html
