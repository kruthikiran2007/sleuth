"""Tests for sleuth.report_html — self-contained HTML reports."""

import html

import pytest

from sleuth import __version__
from sleuth.report_html import render_html, write_html


def _full_report():
    """Synthetic report covering every section incl. optional YARA/APK."""
    return {
        "path": "/tmp/sample-malware-ish.bin",
        "file_type": "pe",
        "size": 153600,
        "string_count": 482,
        "verdict": "SUSPICIOUS",
        "score": 42,
        "signals": [
            {
                "points": 20,
                "evidence": "<script>alert(1)</script>",
                "detail": "payload with <angle> brackets in detail",
            },
            {
                "points": 5,
                "evidence": "import: VirtualAlloc",
                "detail": "suspicious import",
            },
        ],
        "secrets": [
            {"type": "aws_access_key", "preview": "AKIA...", "line": 3},
        ],
        "yara_matches": [
            {"rule": "susp_upx_pack", "severity": "medium", "matches": 2},
            {"rule": "evil<string>", "severity": "high", "matches": 1},
        ],
        "apk": {
            "package": "com.evil.app",
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.SEND_SMS",
            ],
            "dangerous_permissions": ["android.permission.SEND_SMS"],
            "risky_combos": [["SEND_SMS", "READ_CONTACTS"]],
            "debuggable": True,
        },
        "anatomy": {
            "available": True,
            "sections": [
                {"name": ".text", "size": 98304, "entropy": 6.8},
                {"name": ".rsrc", "size": 2048, "entropy": 3.1},
            ],
            "mitigations": {"ASLR": True, "DEP": False},
        },
        "indicators": {
            "ips": ["192.0.2.44"],
            "urls": ["http://example.com/c2"],
        },
    }


def test_write_html_structure(tmp_path):
    out = tmp_path / "report.html"
    ret = write_html(_full_report(), str(out))
    assert ret == str(out)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")
    assert content.rstrip().endswith("</html>")
    # Optional sections present when data present.
    assert "YARA matches" in content
    assert "susp_upx_pack" in content
    assert "APK details" in content
    assert "com.evil.app" in content
    assert "android.permission.SEND_SMS" in content
    # Footer limitations note.
    assert "Static analysis only" in content
    assert "Sleuth never executes the target" in content
    assert "Sleuth" in content and __version__ in content


def test_html_escaping_of_payloads():
    content = render_html(_full_report())
    # Injected markup must be escaped, never raw.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "<script>alert(1)</script>" not in content
    assert "evil&lt;string&gt;" in content
    assert "evil<string>" not in content
    assert "&lt;angle&gt;" in content
    # Redacted secret preview present; module never receives raw values.
    assert "AKIA..." in content


def test_raw_secret_never_printed_raw():
    planted = "x9Kq2-pl4nt3d-s3cr3t-v4lu3"
    report = _full_report()
    report["signals"] = [
        {"points": 1, "evidence": planted,
         "detail": "payload <b>%s</b>" % planted},
    ]
    content = render_html(report)
    # Even if a secret lands in a signal field, the module's contract is
    # HTML-escaping: markup in it cannot break out of the document.
    assert "<b>%s</b>" % planted not in content
    assert html.escape(planted, quote=True) in content
    assert "&lt;b&gt;" in content


def test_verdict_badge_color():
    content = render_html(_full_report())
    assert "SUSPICIOUS" in content
    assert "#9a6700" in content  # amber hex for SUSPICIOUS
    clean = dict(_full_report(), verdict="CLEAN", score=3)
    assert "#1a7f37" in render_html(clean)
    bad = dict(_full_report(), verdict="MALICIOUS-LOOKING", score=80)
    assert "#b42318" in render_html(bad)


def test_missing_optional_keys_render_cleanly():
    report = _full_report()
    del report["yara_matches"]
    del report["apk"]
    content = render_html(report)  # must not raise KeyError
    assert "YARA matches" not in content
    assert "APK details" not in content
    assert content.startswith("<!DOCTYPE html>")


def test_empty_optional_lists_omit_sections():
    report = _full_report()
    report["yara_matches"] = []
    report["apk"] = {}
    content = render_html(report)
    assert "YARA matches" not in content
    assert "APK details" not in content


def test_no_external_requests_in_output():
    content = render_html(_full_report())
    lowered = content.lower()
    # Indicator URLs are escaped text content, not resources. No actual
    # external resource loading anywhere in the document shell.
    assert "<link" not in lowered
    assert "@import" not in lowered
    assert "<script" not in lowered
    assert "cdn." not in lowered
    assert "fonts.googleapis" not in lowered
    assert "<img" not in lowered
