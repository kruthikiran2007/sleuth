"""Tests for file-type detection (magic bytes)."""

import os

import pytest

from sleuth import detect


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_detect_elf(tmp_path):
    p = _write(tmp_path, "a.elf", b"\x7fELF" + b"\x00" * 100)
    assert detect.detect_type(p) == "elf"


def test_detect_pe(tmp_path):
    p = _write(tmp_path, "a.exe", b"MZ" + b"\x00" * 100)
    assert detect.detect_type(p) == "pe"


def test_detect_macho(tmp_path):
    p = _write(tmp_path, "a.macho", b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
    assert detect.detect_type(p) == "macho"


def test_detect_zip(tmp_path):
    p = _write(tmp_path, "a.zip", b"PK\x03\x04" + b"\x00" * 100)
    assert detect.detect_type(p) == "zip"


def test_detect_apk_flavor(tmp_path):
    # ZIP containing AndroidManifest.xml is reported as apk.
    blob = b"PK\x03\x04" + b"\x00" * 50 + b"AndroidManifest.xml" + b"\x00" * 50
    p = _write(tmp_path, "a.apk", blob)
    assert detect.detect_type(p) == "apk"


def test_detect_script(tmp_path):
    p = _write(tmp_path, "run.sh", b"#!/bin/bash\necho hello\n")
    assert detect.detect_type(p) == "script"


def test_detect_text(tmp_path):
    p = _write(tmp_path, "notes.txt", b"hello world, this is plain text\n")
    assert detect.detect_type(p) == "text"


def test_detect_unknown(tmp_path):
    # Random binary bytes: not text, no known magic.
    p = _write(tmp_path, "blob.bin", bytes(range(256)) * 4)
    assert detect.detect_type(p) == "unknown"


def test_size_gate_ok(tmp_path):
    p = _write(tmp_path, "small.bin", b"hello")
    ok, size = detect.check_size_ok(p)
    assert ok and size == 5


def test_size_gate_refuses_large(monkeypatch, tmp_path):
    p = _write(tmp_path, "big.bin", b"x")
    monkeypatch.setattr(detect, "MAX_FILE_SIZE", 0)
    ok, _ = detect.check_size_ok(p)
    assert not ok
