"""Tests for sleuth.folder_scan (Feature 1: folder scan mode).

Never executes any target: all fixtures are static byte blobs built with
tests/pe_builder.py or plain text.
"""

import json
import os

import pytest

from sleuth import cli, folder_scan
from tests.pe_builder import build_pe


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def triage_folder(tmp_path):
    """Folder with clean / suspicious / malicious-looking fixtures."""
    # Clean: minimal PE, no imports, nothing suspicious.
    _write(tmp_path, "clean.exe",
           build_pe(imports={}, extra=b"hello world program"))
    # Suspicious: memory-allocation primitive import.
    _write(tmp_path, "shady.dll",
           build_pe(imports={"kernel32.dll": ["VirtualAlloc"]},
                    extra=b"helper library"))
    # Malicious-looking: full process-injection chain + leaked token.
    evil = (b"ghp_" + b"A" * 36 + b"\x00"
            b"CreateRemoteThread marker payload")
    _write(tmp_path, "evil.exe",
           build_pe(
               imports={"kernel32.dll": ["VirtualAlloc",
                                        "WriteProcessMemory",
                                        "CreateRemoteThread"]},
               extra=evil))
    # Not executable: skipped.
    _write(tmp_path, "readme.txt", b"just a text file\n")
    return str(tmp_path)


def test_scan_ranking_order(triage_folder):
    scan = folder_scan.scan_folder(triage_folder)
    names = [os.path.basename(e["path"]) for e in scan["files"]]
    assert names == ["evil.exe", "shady.dll", "clean.exe"]
    scores = [e["score"] for e in scan["files"]]
    assert scores == sorted(scores, reverse=True)


def test_scan_counts(triage_folder):
    scan = folder_scan.scan_folder(triage_folder)
    assert scan["counts"]["scanned"] == 3
    assert scan["counts"]["malicious_looking"] == 1
    assert scan["skipped"]["not_executable"] == 1


def test_scan_too_large_skipped(tmp_path, monkeypatch):
    from sleuth import detect

    _write(tmp_path, "big.exe", build_pe())
    monkeypatch.setattr(detect, "MAX_FILE_SIZE", 10)
    scan = folder_scan.scan_folder(str(tmp_path))
    assert scan["counts"]["scanned"] == 0
    assert scan["skipped"]["too_large"] == 1


def test_scan_symlink_outside_skipped(tmp_path):
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    outside = tmp_path / "outside"  # sibling of scan root, NOT inside it
    outside.mkdir()
    secret = outside / "secret.exe"
    secret.write_bytes(build_pe())
    link = scan_root / "sneaky.exe"
    try:
        os.symlink(str(secret), str(link))
    except OSError:
        pytest.skip("symlinks not permitted on this platform")
    scan = folder_scan.scan_folder(str(scan_root))
    assert scan["skipped"]["symlink_outside"] == 1
    assert scan["counts"]["scanned"] == 0
    assert all("sneaky.exe" not in e["path"] for e in scan["files"])


def test_scan_not_a_directory():
    with pytest.raises(FileNotFoundError):
        folder_scan.scan_folder("/no/such/dir")


def test_scan_cli(triage_folder, capsys):
    assert cli.main(["scan", triage_folder]) == 0
    out = capsys.readouterr().out
    assert "folder scan" in out
    assert "evil.exe" in out
    # Worst-first: evil.exe line appears before clean.exe line.
    assert out.index("evil.exe") < out.index("clean.exe")


def test_scan_cli_json(triage_folder, capsys):
    assert cli.main(["scan", triage_folder, "--json"]) == 0
    scan = json.loads(capsys.readouterr().out)
    assert scan["counts"]["scanned"] == 3


def test_scan_cli_html(triage_folder, tmp_path):
    out = str(tmp_path / "scan.html")
    assert cli.main(["scan", triage_folder, "--html", out]) == 0
    html = open(out, encoding="utf-8").read()
    assert "evil.exe" in html
    assert "MALICIOUS-LOOKING" in html


def test_scan_verbose_includes_signals(triage_folder):
    scan = folder_scan.scan_folder(triage_folder, verbose=True)
    evil = scan["files"][0]
    assert evil["signals"], "verbose mode should attach per-file signals"
    scan2 = folder_scan.scan_folder(triage_folder, verbose=False)
    assert "signals" not in scan2["files"][0]


def test_is_candidate():
    assert folder_scan.is_candidate("/x/tool.exe")
    assert folder_scan.is_candidate("/x/script.ps1")
    assert not folder_scan.is_candidate("/x/notes.txt")
