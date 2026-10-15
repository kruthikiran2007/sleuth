"""Tests for the CLI: exit codes and subcommands."""

import sys

import pytest

from sleuth import cli


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_analyze_text_file(tmp_path, capsys):
    p = _write(tmp_path, "note.txt", b"hello world\njust a text file\n")
    assert cli.main(["analyze", p]) == 0
    out = capsys.readouterr().out
    assert "VERDICT: CLEAN" in out
    assert "type: text" in out


def test_analyze_json(tmp_path, capsys):
    import json

    p = _write(tmp_path, "note.txt", b"hello\n")
    assert cli.main(["analyze", p, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "CLEAN"
    assert report["file_type"] == "text"


def test_analyze_missing_file(capsys):
    assert cli.main(["analyze", "/no/such/file.bin"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_analyze_too_large(tmp_path, monkeypatch, capsys):
    from sleuth import detect

    p = _write(tmp_path, "big.bin", b"x" * 10)
    monkeypatch.setattr(detect, "MAX_FILE_SIZE", 5)
    assert cli.main(["analyze", p]) == 1
    assert "refusing" in capsys.readouterr().err.lower()


def test_strings_command(tmp_path, capsys):
    p = _write(tmp_path, "a.bin", b"\x00hello\x00world!!\x00")
    assert cli.main(["strings", p]) == 0
    out = capsys.readouterr().out
    assert "hello" in out and "world!!" in out


def test_secrets_command_finds_key(tmp_path, capsys):
    p = _write(tmp_path, "leak.txt", b"key=AKIAIOSFODNN7EXAMPLE\n")
    assert cli.main(["secrets", p]) == 0
    out = capsys.readouterr().out
    assert "aws_access_key" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out  # redacted


def test_secrets_command_clean(tmp_path, capsys):
    p = _write(tmp_path, "clean.txt", b"nothing to see here\n")
    assert cli.main(["secrets", p]) == 0
    assert "No known secret" in capsys.readouterr().out


def test_no_subcommand_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_analyze_detects_elf(tmp_path, capsys):
    p = _write(tmp_path, "a.elf", b"\x7fELF" + b"\x00" * 64)
    assert cli.main(["analyze", p]) == 0
    assert "type: elf" in capsys.readouterr().out


def test_yara_command_clean_file(tmp_path, capsys):
    p = _write(tmp_path, "clean.bin", b"hello world, nothing to see here\n")
    assert cli.main(["yara", p]) == 0
    out = capsys.readouterr().out
    assert "No YARA rules matched" in out


def test_yara_command_match(tmp_path, capsys):
    pytest.importorskip("yara")
    p = _write(tmp_path, "packed.bin", b"\x00UPX!\x00data\x00")
    assert cli.main(["yara", p]) == 0
    assert "upx_packer" in capsys.readouterr().out


def test_analyze_html_report(tmp_path, capsys):
    p = _write(tmp_path, "note.txt", b"hello\n")
    html_path = str(tmp_path / "report.html")
    assert cli.main(["analyze", p, "--html", html_path]) == 0
    assert "HTML report written to" in capsys.readouterr().out
    content = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")
    assert "VERDICT" in content or "CLEAN" in content


def test_analyze_missing_yara_module_degrades(tmp_path, capsys, monkeypatch):
    # analyze must survive even if the yara feature module is absent
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "sleuth.yara_scan":
            raise ImportError("mocked missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    p = _write(tmp_path, "note.txt", b"hello\n")
    assert cli.main(["analyze", p]) == 0
    assert "VERDICT: CLEAN" in capsys.readouterr().out
