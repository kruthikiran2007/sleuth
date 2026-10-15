"""Tests for sleuth.iocs (Feature 3: IOC extraction).

All inputs are crafted plain-text blobs — no live malware, no real
victim data. Wallet addresses below are syntactically valid but
fictional.
"""

import json

import pytest

from sleuth import cli, iocs
from sleuth.iocs import extract_iocs, ioc_summary

BLOB = [
    "connecting to 203.0.113.45 on port 4444",          # public IP, high
    "callback http://evil-example.xyz/gate.php",        # url, medium
    "tor hidden service http://abcdefghijklmnop.onion/x",  # onion, high
    "contact operator@evil-example.xyz for support",    # email, medium
    r"persistence via HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",  # registry high
    r"debug symbols at C:\build\agent\work\payload.pdb",  # pdb high
    r"dropped to C:\Users\Public\update.exe",           # win path low
    "config in /etc/cron.d/updater",                    # unix path low
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",        # UA medium
    "pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",           # BTC high
    "pay 0x" + "ab" * 20,                                     # ETH high
    "benign vendor link https://www.microsoft.com/en-us",  # known-good low
    "internal host 192.168.1.50",                       # private IP low
]

BENIGN = [
    "hello world",
    "version 1.2.3",
    "copyright 2024 acme corp",
]


def test_all_types_extracted():
    found = extract_iocs(BLOB)
    assert found["ipv4"][0]["value"] == "203.0.113.45"
    assert found["ipv4"][0]["confidence"] == "high"
    assert any(i["value"].startswith("http://evil-example.xyz")
               for i in found["url"])
    assert any(i["confidence"] == "high" and ".onion" in i["value"]
               for i in found["url"])
    assert found["email"][0]["value"] == "operator@evil-example.xyz"
    assert any("Run" in i["value"] and i["confidence"] == "high"
               for i in found["registry"])
    assert found["pdb_path"][0]["confidence"] == "high"
    assert any(i["value"].endswith("update.exe")
               for i in found["file_path"])
    assert any("/etc/cron.d/updater" in i["value"]
               for i in found["file_path"])
    assert found["user_agent"][0]["confidence"] == "medium"
    assert found["wallet_btc"][0]["confidence"] == "high"
    assert found["wallet_eth"][0]["confidence"] == "high"


def test_known_good_domain_is_low():
    found = extract_iocs(["see https://www.microsoft.com/en-us for details"])
    urls = found.get("url", [])
    assert urls and urls[0]["confidence"] == "low"


def test_private_ip_is_low():
    found = extract_iocs(["gateway 192.168.1.1"])
    assert found["ipv4"][0]["confidence"] == "low"


def test_version_number_not_confident_ip():
    # "5.1.0.0" looks exactly like an IP — in a version string it must be
    # downgraded, with the ambiguity stated honestly.
    found = extract_iocs(["FileVersion 5.1.0.0 built 2024"])
    assert found["ipv4"][0]["value"] == "5.1.0.0"
    assert found["ipv4"][0]["confidence"] == "low"
    assert "version" in found["ipv4"][0]["note"].lower()


def test_benign_blob_has_no_high_confidence():
    found = extract_iocs(BENIGN)
    for items in found.values():
        for item in items:
            assert item["confidence"] != "high"


def test_dedup_and_order():
    found = extract_iocs(["ip 203.0.113.45", "again 203.0.113.45"])
    assert len(found["ipv4"]) == 1


def test_empty_input():
    assert extract_iocs([]) == {}
    assert extract_iocs(None) == {}


def test_summary():
    found = extract_iocs(["ip 203.0.113.45"])
    assert "ipv4" in ioc_summary(found)
    assert ioc_summary({}) == "none"


def test_iocs_cli(tmp_path, capsys):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"\x00".join(s.encode() for s in BLOB) + b"\x00")
    assert cli.main(["iocs", str(p)]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.45" in out
    assert "wallet_btc" in out


def test_iocs_cli_json(tmp_path, capsys):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"\x00contact evil@evil-example.xyz\x00")
    assert cli.main(["iocs", str(p), "--json"]) == 0
    found = json.loads(capsys.readouterr().out)
    assert found["email"][0]["value"] == "evil@evil-example.xyz"


def test_iocs_in_analyze_report(tmp_path, capsys):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"\x00connecting to 203.0.113.45\x00")
    assert cli.main(["analyze", str(p), "--json", "--no-intel"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "iocs" in report
    assert report["iocs"]["ipv4"][0]["value"] == "203.0.113.45"
