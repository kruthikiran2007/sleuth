"""Leaked-secret scanning with regular expressions.

Each pattern looks for a well-known secret format (AWS keys, GitHub tokens,
private keys, ...). Matches are reported with a REDACTED preview — the first
4 characters plus "..." — so a real secret is never printed in full into
logs or reports.

A regex match is a *candidate*, not proof: test keys and documentation
examples also match. The verdict engine treats them as one signal among many.
"""

import re

# (name, compiled_regex). Keep patterns tight to avoid false positives.
_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("discord_webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]")),
    ("password_in_url", re.compile(r"(?i)\bhttps?://[^/\s:]+:([^@/\s]{4,})@")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("stripe_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
]


def redact(secret):
    """Redact a secret for safe display: first 4 chars + '...'.

    Never print a full secret — it could end up in logs, screenshots, or
    shared reports.
    """
    secret = str(secret)
    if len(secret) <= 4:
        return "****"
    return secret[:4] + "..."


def scan_secrets(text):
    """Scan *text* for known secret formats.

    Returns a list of dicts: {"type": name, "preview": redacted, "line": n}.
    Empty list means no known secret format was found (not a guarantee).
    """
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                # Prefer the captured group (the actual secret) when present.
                secret = match.group(1) if match.lastindex else match.group(0)
                findings.append(
                    {"type": name, "preview": redact(secret), "line": lineno}
                )
    return findings
