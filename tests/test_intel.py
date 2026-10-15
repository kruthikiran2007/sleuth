"""Tests for the MalwareBazaar threat-intel lookup.

The HTTP layer is always mocked — these tests never touch the real API.
The suite-wide conftest stubs ``threat_intel.lookup`` offline; this module
captures the real function at import time (before any fixture runs) so it
can test the real lookup logic with an injected fake urlopen.
"""

import hashlib
import io
import json
import urllib.error

import pytest

from sleuth import threat_intel

# Real function, captured before conftest's autouse fixture stubs it.
_REAL_LOOKUP = threat_intel.lookup


def _fake_urlopen_factory(body_bytes=None, exc=None):
    def fake_urlopen(request, timeout=None):
        if exc is not None:
            raise exc
        captured.append({"url": request.full_url,
                         "payload": json.loads(request.data.decode())})
        return _FakeResponse(body_bytes)

    captured = []
    fake_urlopen.captured = captured
    return fake_urlopen


class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


_KNOWN_BODY = json.dumps({
    "query_status": "ok",
    "data": [{
        "sha256_hash": "ab" * 32,
        "signature": "Emotet",
        "tags": ["trojan", "emotet"],
        "first_seen": "2024-01-02 03:04:05",
        "reporter": "abuse_ch",
    }],
}).encode()

_UNKNOWN_BODY = json.dumps({"query_status": "hash_not_found"}).encode()


def test_sha256_file(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"hello")
    assert threat_intel.sha256_file(str(p)) == hashlib.sha256(b"hello").hexdigest()


def test_query_known_malware():
    fake = _fake_urlopen_factory(_KNOWN_BODY)
    result = threat_intel.query_malwarebazaar("ab" * 32, urlopen=fake)
    assert result["available"] is True
    assert result["known"] is True
    assert result["family"] == "Emotet"
    assert "trojan" in result["tags"]
    assert result["first_seen"] == "2024-01-02 03:04:05"
    # Only the hash is sent, as a get_info query.
    assert fake.captured[0]["payload"] == {"query": "get_info", "hash": "ab" * 32}
    assert fake.captured[0]["url"] == threat_intel.API_URL


def test_query_unknown_hash():
    fake = _fake_urlopen_factory(_UNKNOWN_BODY)
    result = threat_intel.query_malwarebazaar("cd" * 32, urlopen=fake)
    assert result["available"] is True
    assert result["known"] is False
    assert result["family"] is None


def test_query_timeout_is_offline_safe():
    fake = _fake_urlopen_factory(
        exc=urllib.error.URLError("timed out"))
    result = threat_intel.query_malwarebazaar("ef" * 32, urlopen=fake)
    assert result["available"] is False
    assert result["known"] is False
    assert "offline" in result["reason"]


def test_query_garbage_response():
    fake = _fake_urlopen_factory(b"not json{{{")
    result = threat_intel.query_malwarebazaar("12" * 32, urlopen=fake)
    assert result["available"] is False
    assert result["known"] is False


def test_intel_signal_known_forces_malicious():
    result = {"available": True, "known": True, "sha256": "ab" * 32,
              "family": "Emotet", "tags": ["trojan"],
              "first_seen": None, "reporter": None}
    signals = threat_intel.intel_signal(result)
    assert len(signals) == 1
    assert signals[0]["points"] >= 60  # forces MALICIOUS-LOOKING band
    assert "Emotet" in signals[0]["evidence"]
    assert "MalwareBazaar" in signals[0]["evidence"]


def test_intel_signal_unknown_is_empty():
    assert threat_intel.intel_signal({"known": False}) == []


def test_lookup_end_to_end_known(monkeypatch, tmp_path):
    """Real lookup() with a mocked HTTP layer (undoes conftest stub)."""
    monkeypatch.setattr(threat_intel, "lookup", _REAL_LOOKUP)
    p = tmp_path / "x.bin"
    p.write_bytes(b"evil-bytes")
    fake = _fake_urlopen_factory(_KNOWN_BODY)
    monkeypatch.setattr("urllib.request.urlopen", fake)
    result = threat_intel.lookup(str(p))
    assert result["known"] is True
    assert result["sha256"] == hashlib.sha256(b"evil-bytes").hexdigest()


def test_lookup_missing_file(monkeypatch):
    monkeypatch.setattr(threat_intel, "lookup", _REAL_LOOKUP)
    result = threat_intel.lookup("/no/such/file.bin")
    assert result["available"] is False
    assert result["known"] is False
