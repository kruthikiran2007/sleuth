"""MalwareBazaar known-malware lookup for Sleuth.

SHA256-hashes the target and asks MalwareBazaar (abuse.ch)
``https://mb-api.abuse.ch/api/v1/`` whether the hash is a known malware
sample. This is the ONLY Sleuth feature that touches the network.

Fully offline-safe: any network error, timeout, or unexpected response
yields ``{"available": False, "reason": ...}`` and analysis continues.
Uses only the standard library (urllib). Nothing is uploaded except the
SHA256 hash — the file itself never leaves the machine.

A "known malware" hit is strong evidence: the caller (analyze.py) turns it
into a high-weight signal that forces the verdict to MALICIOUS-LOOKING.
"""

import hashlib
import json
import os
import urllib.request
import urllib.error

API_URL = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 10  # seconds

# Points for a confirmed known-malware hit: enough to force the
# MALICIOUS-LOOKING verdict band (>= 60) on its own.
KNOWN_MALWARE_POINTS = 60


def sha256_file(path, chunk_size=65536):
    """Return the hex SHA256 digest of *path* (streamed, read-only)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def query_malwarebazaar(sha256, timeout=TIMEOUT, urlopen=None):
    """Query MalwareBazaar for *sha256*.

    Returns a dict::

        {"available": bool, "reason": str (when unavailable),
         "known": bool, "sha256": str,
         "family": str|None, "tags": [str],
         "first_seen": str|None, "reporter": str|None}

    ``urlopen`` is injectable for tests (defaults to urllib.request.urlopen).
    Never raises.
    """
    opener = urlopen or urllib.request.urlopen
    payload = json.dumps({"query": "get_info", "hash": sha256}).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": "sleuth-static-triage/0.3"},
        method="POST",
    )
    try:
        with opener(request, timeout=timeout) as response:
            body = response.read()
    except Exception as exc:
        return {
            "available": False,
            "reason": "threat intel unavailable (%s) — offline?" % exc,
            "known": False,
            "sha256": sha256,
        }
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return {
            "available": False,
            "reason": "threat intel returned an unreadable response",
            "known": False,
            "sha256": sha256,
        }
    status = data.get("query_status")
    if status == "ok":
        samples = data.get("data") or []
        sample = samples[0] if samples else {}
        tags = sample.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        return {
            "available": True,
            "known": True,
            "sha256": sha256,
            "family": sample.get("signature"),
            "tags": [str(t) for t in tags],
            "first_seen": sample.get("first_seen"),
            "reporter": sample.get("reporter"),
        }
    if status in ("hash_not_found", "no_results"):
        return {
            "available": True,
            "known": False,
            "sha256": sha256,
            "family": None,
            "tags": [],
            "first_seen": None,
            "reporter": None,
        }
    return {
        "available": False,
        "reason": "threat intel query failed (status: %s)" % status,
        "known": False,
        "sha256": sha256,
    }


def lookup(path, timeout=TIMEOUT, urlopen=None):
    """Hash *path* and look it up on MalwareBazaar. Never raises."""
    try:
        digest = sha256_file(path)
    except OSError as exc:
        return {
            "available": False,
            "reason": "cannot read file: %s" % exc,
            "known": False,
            "sha256": "",
        }
    return query_malwarebazaar(digest, timeout=timeout, urlopen=urlopen)


def intel_signal(result):
    """Convert a lookup() result to Sleuth signal dicts (possibly empty).

    A confirmed known-malware hit contributes KNOWN_MALWARE_POINTS, which
    forces the MALICIOUS-LOOKING verdict band on its own.
    """
    if not result.get("known"):
        return []
    family = result.get("family") or "unknown family"
    tags = result.get("tags") or []
    detail = "SHA256 %s is a known malware sample on MalwareBazaar " % (
        result.get("sha256", "")[:16] + "..."
    )
    detail += "(family: %s%s)." % (
        family,
        (", tags: %s" % ", ".join(tags[:5])) if tags else "",
    )
    return [
        {
            "points": KNOWN_MALWARE_POINTS,
            "evidence": "MalwareBazaar: hash is known malware (%s)" % family,
            "detail": detail,
        }
    ]
