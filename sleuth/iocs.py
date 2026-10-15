"""Indicator-of-Compromise (IOC) extraction from printable strings.

Pulls out the artifacts incident responders care about: IP addresses,
URLs/domains, emails, registry paths, file paths, PDB debug paths,
User-Agent strings, and cryptocurrency wallet addresses. Everything is
deduplicated, classified by type, and labeled with a confidence level.

Confidence is about *analyst interest*, not certainty of malice:
- high:   worth a closer look (public IP, .onion domain, Run-key registry
           path, PDB path, wallet address)
- medium: potentially interesting, often benign (ordinary URL, email)
- low:    likely noise (private IP, well-known vendor domain, something
           that merely *looks* like an IP — e.g. a version number)

These are LEADS for a human, never verdicts by themselves. Sleuth does
not score IOCs into the verdict — that job belongs to the heuristics
engine, which already weighs a couple of these weakly. The honesty rule:
residual noise is documented, not hidden (see README).
"""

import re

# --- Patterns ------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_URL_RE = re.compile(r"https?://[^\s'\"<>\\]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"(?:com|net|org|io|ru|cn|su|biz|info|dev|app|xyz|top|tk|ml|ga|cf|gq|"
    r"onion|in|co|us|uk|de|fr|nl|se|ch|cc|me|tv|pw|ws|site|online|tech|"
    r"store|club|pro|[a-z]{2,6})\b",
    re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)[\\/](?:[^\\/\s\"'<>|]+[\\/]?)+",
    re.IGNORECASE)
_WINPATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"'<>|]+")
_UNIXPATH_RE = re.compile(
    r"(?:/(?:usr|etc|var|tmp|home|root|opt|bin|sbin|lib|proc|sys|dev|run)"
    r"(?:/[^\s\"'<>|]+)?)")
_UA_RE = re.compile(
    r"\bMozilla/\d\.\d[^\s\"']{0,120}|User-Agent\s*[:=]\s*[^\s\"']+",
    re.IGNORECASE)
_BTC_RE = re.compile(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_VERSION_HINT_RE = re.compile(r"version", re.IGNORECASE)

# Domains so common they are almost never interesting on their own.
_KNOWN_GOOD_DOMAINS = {
    "microsoft.com", "windows.com", "google.com", "apple.com",
    "github.com", "gnu.org", "python.org", "w3.org", "ietf.org",
    "schemas.microsoft.com", "go.microsoft.com", "aka.ms",
    "translationproject.org",
}


def _is_known_good(domain):
    """True for well-known vendor domains, including their subdomains."""
    domain = (domain or "").lower()
    if domain in _KNOWN_GOOD_DOMAINS:
        return True
    return any(domain.endswith("." + good)
               for good in _KNOWN_GOOD_DOMAINS)

# Registry locations malware loves (persistence / autostart).
_HOT_REGISTRY_HINTS = (
    "run", "runonce", "winlogon", "policies\\explorer",
    "currentversion\\run",
)

# Private / reserved IPv4 ranges — interesting for lateral movement, but
# usually just local config. Labeled low, never hidden.
def _is_private_ip(ip):
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return True
    if len(parts) != 4 or any(p > 255 for p in parts):
        return True
    a, b = parts[0], parts[1]
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
        or (a == 169 and b == 254)
        or a == 0
    )


def _valid_ip(ip):
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False


def _domain_of(url):
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
    host = host.split("@")[-1].split(":")[0].lower()
    return host


def extract_iocs(strings):
    """Extract IOCs from a list of printable strings.

    Returns a dict mapping IOC type -> list of
    {"value": str, "confidence": "high|medium|low", "note": str}.
    Deduplicated, order of first appearance preserved. Never raises.
    """
    found = {}  # type -> {value -> entry}

    def add(ioc_type, value, confidence, note):
        bucket = found.setdefault(ioc_type, {})
        if value not in bucket:
            bucket[value] = {"value": value, "confidence": confidence,
                             "note": note}

    for s in strings or []:
        try:
            _scan_string(s, add)
        except Exception:
            continue

    return {k: list(v.values()) for k, v in found.items()}


def _scan_string(s, add):
    # IPv4.
    for m in _IPV4_RE.finditer(s):
        ip = m.group(0)
        if not _valid_ip(ip):
            continue
        if _VERSION_HINT_RE.search(s):
            add("ipv4", ip, "low",
                "looks like an IP but sits in a version string — "
                "probably a version number, not an address")
        elif _is_private_ip(ip):
            add("ipv4", ip, "low", "private/reserved address")
        else:
            add("ipv4", ip, "high", "hardcoded public IP address")

    # IPv6 (kept separate; rarer and noisier).
    for m in _IPV6_RE.finditer(s):
        ip = m.group(0)
        if "::" in ip or ip.count(":") >= 2:
            add("ipv6", ip, "medium", "hardcoded IPv6 address")

    # URLs + their domains.
    for m in _URL_RE.finditer(s):
        url = m.group(0).rstrip(".,;)")
        domain = _domain_of(url)
        if domain.endswith(".onion"):
            add("url", url, "high", "Tor hidden-service URL")
        elif _is_known_good(domain):
            add("url", url, "low", "well-known vendor domain")
        else:
            add("url", url, "medium", "hardcoded URL — review destination")
        if domain and not _is_known_good(domain):
            conf = "high" if domain.endswith(".onion") else "medium"
            add("domain", domain, conf, "domain seen in binary")

# Bare domains (not inside a URL we already captured).
    for m in _DOMAIN_RE.finditer(s):
        domain = m.group(0).lower()
        if _URL_RE.search(s):
            continue  # already captured via the URL pass
        if re.search(r"\.(dll|so|dylib|exe|sys|drv|ocx|cpl)$", domain):
            continue  # library filename (kernel32.dll), not a domain
        if _is_known_good(domain):
            add("domain", domain, "low", "well-known vendor domain")
        else:
            conf = "high" if domain.endswith(".onion") else "medium"
            add("domain", domain, conf, "bare domain in strings")

    # Emails.
    for m in _EMAIL_RE.finditer(s):
        add("email", m.group(0), "medium", "email address in binary")

    # Registry paths.
    for m in _REGISTRY_RE.finditer(s):
        path = m.group(0).rstrip("\\/")
        lowered = path.lower()
        if any(h in lowered for h in _HOT_REGISTRY_HINTS):
            add("registry", path, "high",
                "autostart/persistence registry location")
        else:
            add("registry", path, "medium", "Windows registry path")

    # File paths.
    for m in _WINPATH_RE.finditer(s):
        path = m.group(0).rstrip("\\.,;)")
        if path.lower().endswith(".pdb"):
            add("pdb_path", path, "high",
                "PDB debug path — leaks the author's build machine layout")
        else:
            add("file_path", path, "low", "hardcoded Windows path")
    for m in _UNIXPATH_RE.finditer(s):
        add("file_path", m.group(0).rstrip("/.,;)"), "low",
            "hardcoded Unix path")

    # User-Agent strings.
    for m in _UA_RE.finditer(s):
        ua = m.group(0)[:120]
        add("user_agent", ua, "medium", "HTTP User-Agent string")

    # Crypto wallets.
    for m in _BTC_RE.finditer(s):
        add("wallet_btc", m.group(0), "high",
            "Bitcoin address — check for ransom/extortion context")
    for m in _ETH_RE.finditer(s):
        add("wallet_eth", m.group(0), "high",
            "Ethereum address — check for ransom/extortion context")


def ioc_summary(iocs):
    """One-line human summary, e.g. '3 ipv4, 1 url, 2 registry'."""
    parts = []
    for ioc_type in sorted(iocs):
        n = len(iocs[ioc_type])
        parts.append("%d %s" % (n, ioc_type))
    return ", ".join(parts) if parts else "none"
