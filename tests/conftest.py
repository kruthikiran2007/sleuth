"""Shared test fixtures for the Sleuth suite.

The MalwareBazaar lookup is the only Sleuth feature that touches the
network. To keep the suite hermetic (fast, offline-safe, and polite to
abuse.ch), every test runs with ``threat_intel.lookup`` stubbed to the
offline/unavailable result — unless the test explicitly restores the real
function (see tests/test_intel.py, which captures the original at import
time and injects a fake urlopen).

capa *does* run for real in tests that analyze PE/ELF inputs (it is a
local, read-only engine), and degrades gracefully on garbage inputs.
"""

import pytest


def _offline_lookup(path, timeout=10, urlopen=None):
    return {
        "available": False,
        "reason": "threat intel unavailable (mocked offline for tests)",
        "known": False,
        "sha256": "00" * 32,
    }


@pytest.fixture(autouse=True)
def _offline_threat_intel(monkeypatch):
    from sleuth import threat_intel

    monkeypatch.setattr(threat_intel, "lookup", _offline_lookup)
