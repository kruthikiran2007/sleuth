"""Tests for sleuth.signature (Feature 2: Authenticode certificate check).

Never executes any target: fixtures are static PEs from tests/pe_builder.py
with a hand-appended (fake) certificate table.
"""

import struct

import pytest

from sleuth import cli, signature
from tests.pe_builder import build_pe


def _add_cert_table(pe_bytes, blob=b"CN=FakeSigner,O=FakeOrg"):
    """Append a WIN_CERTIFICATE blob and point data directory #4 at it."""
    out = bytearray(pe_bytes)
    # Data directories start at 64 (DOS) + 4 (PE sig) + 20 (COFF) + 96
    # (optional fixed) = 184; each entry is 8 bytes; cert table is #4.
    dir4_offset = 184 + 4 * 8
    cert_offset = len(out)
    cert = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0002) + blob
    # WIN_CERTIFICATE length is 8-byte aligned.
    pad = (-len(cert)) % 8
    cert += b"\x00" * pad
    struct.pack_into("<II", out, dir4_offset, cert_offset, len(cert))
    return bytes(out) + cert


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_unsigned_pe(tmp_path):
    p = _write(tmp_path, "tool.exe", build_pe())
    result = signature.check_signature(p)
    assert result["available"] is True
    assert result["signed"] is False
    assert result["cert_size"] == 0
    assert result["signals"] == []


def test_signed_pe(tmp_path):
    p = _write(tmp_path, "tool.exe", _add_cert_table(build_pe()))
    result = signature.check_signature(p)
    assert result["available"] is True
    assert result["signed"] is True
    assert result["cert_size"] > 0
    assert result["signals"] == []  # signed -> never flagged


def test_signer_hint_extracted(tmp_path):
    p = _write(tmp_path, "tool.exe",
               _add_cert_table(build_pe(), blob=b"CN=Contoso Ltd,O=Contoso"))
    result = signature.check_signature(p)
    assert result["signed"] is True
    assert result["signer_hint"] is not None
    assert "Contoso" in result["signer_hint"]


def test_impersonation_by_filename():
    sigs = signature.impersonation_signals("svchost.exe", None, signed=False)
    assert len(sigs) == 1
    assert sigs[0]["points"] == 20
    assert "svchost.exe" in sigs[0]["evidence"]


def test_impersonation_by_company():
    sigs = signature.impersonation_signals(
        "totally-legit.exe", "Microsoft Corporation", signed=False)
    assert len(sigs) == 1
    assert "Microsoft Corporation" in sigs[0]["evidence"]


def test_no_impersonation_when_signed():
    assert signature.impersonation_signals(
        "svchost.exe", "Microsoft Corporation", signed=True) == []


def test_no_impersonation_for_plain_unsigned():
    assert signature.impersonation_signals(
        "myapp.exe", None, signed=False) == []
    assert signature.impersonation_signals(
        "myapp.exe", "Acme Corp", signed=False) == []


def test_elf_is_na(tmp_path):
    p = _write(tmp_path, "tool.elf", b"\x7fELF" + b"\x00" * 64)
    result = signature.check_signature(p)
    assert result["available"] is False
    assert "PE-only" in result["reason"]


def test_non_pe_file_is_na(tmp_path):
    p = _write(tmp_path, "note.txt", b"hello world\n")
    result = signature.check_signature(p)
    assert result["available"] is False


def test_impersonation_folds_into_analyze(tmp_path, capsys):
    # Unsigned binary wearing a system name -> +20 in the verdict.
    p = _write(tmp_path, "svchost.exe", build_pe())
    assert cli.main(["analyze", p, "--no-intel"]) == 0
    out = capsys.readouterr().out
    assert "no Authenticode signature" in out
    assert "signed: NO" in out


def test_signature_section_in_json(tmp_path, capsys):
    import json

    p = _write(tmp_path, "app.exe", build_pe())
    assert cli.main(["analyze", p, "--json", "--no-intel"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "signature" in report
    assert report["signature"]["available"] is True
    assert report["signature"]["signed"] is False
