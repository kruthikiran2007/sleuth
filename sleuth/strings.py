"""Printable-string extraction and Shannon entropy.

`extract_strings` works like the classic `strings` command: it walks the raw
bytes and collects runs of printable ASCII characters. `shannon_entropy`
measures how "random" a byte sequence looks — packed/encrypted sections have
entropy near 8.0, plain code/text sits much lower.
"""

import math
import re
from collections import Counter

# Printable ASCII run, like `strings` with default minimum length.
_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

# Indicators (NOT proof of malice): things often interesting in binaries.
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(rb"https?://[^\s'\"<>\\]+", re.IGNORECASE)


def extract_strings(data, min_len=4):
    """Return a list of printable ASCII strings found in *data*.

    *data* is bytes. Only strings of at least *min_len* characters are kept.
    Pure reading — nothing is executed.
    """
    if min_len != 4:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    else:
        pattern = _STRING_RE
    return [m.group().decode("ascii") for m in pattern.finditer(data)]


def shannon_entropy(data):
    """Shannon entropy of *data* in bits per byte (0.0 .. 8.0).

    Empty input -> 0.0. Uniformly random bytes -> ~8.0.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def find_indicators(strings):
    """Pull out IP addresses and URLs from a string list.

    Returns {"ips": [...], "urls": [...]} — deduplicated, order preserved.
    These are INDICATORS for a human to review, never verdicts by themselves.
    """
    ips, urls = [], []
    seen_ips, seen_urls = set(), set()
    for s in strings:
        raw = s.encode("ascii", errors="ignore")
        for m in IP_RE.finditer(raw):
            ip = m.group().decode("ascii")
            if _valid_ip(ip) and ip not in seen_ips:
                seen_ips.add(ip)
                ips.append(ip)
        for m in URL_RE.finditer(raw):
            url = m.group().decode("ascii")
            if url not in seen_urls:
                seen_urls.add(url)
                urls.append(url)
    return {"ips": ips, "urls": urls}


def _valid_ip(ip):
    """Reject things like 999.999.999.999 that merely look like IPs."""
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except ValueError:
        return False
