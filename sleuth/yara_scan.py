"""YARA rule scanning engine for Sleuth.

Static-only signature scanning: compiled YARA rules are matched against the
raw bytes of a target file. The target is only read from disk — never
executed, loaded, or emulated.

Graceful degradation:
- If ``yara`` (yara-python) is not installed, every function degrades:
  ``status()`` says so, ``load_rules()`` returns None, ``scan_data()``
  returns [], and nothing raises.
- If the ``rules/`` directory is missing or no ``*.yar`` file compiles,
  ``load_rules()`` returns None and scans return [].

The compiled ruleset is cached per directory so repeated scans on the same
rules directory do not recompile.
"""

import os
import re

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

# Absolute path to the starter ruleset, resolved for source tree or install.
from ._paths import rules_dir as _resolve_rules_dir

RULES_DIR = _resolve_rules_dir()

# 200 MB cap mirrors detect.MAX_FILE_SIZE without importing detect.
SCAN_SIZE_LIMIT = 200 * 1024 * 1024

# Points per severity, per the Sleuth signal convention.
_SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 5}

# Cache: rules_dir -> compiled rules object (or None on failure).
_rule_cache = {}


def status():
    """One-line human-readable readiness string for the engine."""
    if not YARA_AVAILABLE:
        return "yara-python not installed — run: pip install yara-python"
    try:
        count = _count_rule_files(RULES_DIR)
    except Exception:
        count = 0
    rules = load_rules()
    if rules is None:
        return "yara ready (0 rules compiled)"
    return "yara ready (%d rules compiled)" % count


def _count_rule_files(rules_dir):
    """Count ``rule`` declarations across all *.yar files in a directory.

    Falls back to the file count if files can't be read. Returns 0 if the
    directory is unreadable.
    """
    try:
        entries = os.listdir(rules_dir)
    except OSError:
        return 0
    yar_files = [f for f in entries if f.lower().endswith(".yar")]
    total = 0
    for fname in yar_files:
        try:
            with open(os.path.join(rules_dir, fname),
                      "r", errors="replace") as f:
                total += len(re.findall(r"(?m)^\s*rule\s+\w+", f.read()))
        except OSError:
            total += 1  # file exists but unreadable; count it as one
    return total


def load_rules(rules_dir=RULES_DIR):
    """Compile every ``*.yar`` file in *rules_dir* into one rules object.

    The result is cached per directory. Returns None when yara-python is
    unavailable, the directory has no .yar files, or compilation fails.
    Never raises.
    """
    if not YARA_AVAILABLE:
        return None
    try:
        rules_dir = os.path.abspath(rules_dir)
    except Exception:
        return None
    if rules_dir in _rule_cache:
        return _rule_cache[rules_dir]
    compiled = None
    try:
        if not os.path.isdir(rules_dir):
            compiled = None
        else:
            filepaths = {}
            for i, fname in enumerate(sorted(os.listdir(rules_dir))):
                if fname.lower().endswith(".yar"):
                    filepaths["ns%d" % i] = os.path.join(rules_dir, fname)
            if filepaths:
                compiled = yara.compile(filepaths=filepaths)
    except Exception:
        compiled = None
    _rule_cache[rules_dir] = compiled
    return compiled


def _string_matches(match):
    """Extract {name, offset, preview} for each matched string."""
    out = []
    try:
        for string_match in match.strings:
            try:
                identifier = string_match.identifier
            except AttributeError:
                identifier = getattr(string_match, "name", "?")
            try:
                instances = string_match.instances
            except AttributeError:
                instances = []
            for inst in instances:
                try:
                    offset = inst.offset
                    data = inst.matched_data
                except AttributeError:
                    offset, data = -1, b""
                preview = data.decode("utf-8", errors="replace")
                if len(preview) > 60:
                    preview = preview[:60]
                out.append(
                    {"name": identifier, "offset": int(offset),
                     "preview": preview}
                )
    except Exception:
        pass
    return out


def scan_data(data, rules_dir=None):
    """Scan *data* (bytes) against the compiled YARA ruleset.

    Returns a list of dicts::

        {"rule": str, "tags": [str], "severity": str,
         "matches": [{"name": str, "offset": int, "preview": str}]}

    ``severity`` comes from the rule's ``meta.severity`` (default "medium").
    ``preview`` is the matched bytes decoded with errors="replace",
    truncated to 60 characters. Returns [] when yara-python is missing,
    no rules compiled, or data is not bytes. Never raises.
    """
    if not YARA_AVAILABLE or not isinstance(data, (bytes, bytearray)):
        return []
    rules = load_rules(RULES_DIR if rules_dir is None else rules_dir)
    if rules is None:
        return []
    results = []
    try:
        for match in rules.match(data=bytes(data)):
            try:
                severity = str(match.meta.get("severity", "medium")).lower()
            except Exception:
                severity = "medium"
            results.append(
                {
                    "rule": match.rule,
                    "tags": list(getattr(match, "tags", []) or []),
                    "severity": severity,
                    "matches": _string_matches(match),
                }
            )
    except Exception:
        return []
    return results


def scan_file(path, rules_dir=None):
    """Read *path* (bytes, capped at SCAN_SIZE_LIMIT) and scan it.

    Returns [] for missing files, files over the cap, or any read error.
    Delegates the actual matching to scan_data. Never raises.
    """
    try:
        size = os.path.getsize(path)
        if size > SCAN_SIZE_LIMIT:
            return []
        with open(path, "rb") as f:
            data = f.read(SCAN_SIZE_LIMIT + 1)
        if len(data) > SCAN_SIZE_LIMIT:
            return []
        return scan_data(data, rules_dir=rules_dir)
    except Exception:
        return []


def yara_signals(matches):
    """Convert scan_data() output to Sleuth signal dicts.

    Each signal: {"points": int, "evidence": str, "detail": str}.
    Points: high=20, medium=10, low=5 (unknown severity -> 10).
    Evidence cites the rule name plus each matched string identifier.
    """
    signals = []
    for hit in matches or []:
        rule = hit.get("rule", "?")
        severity = str(hit.get("severity", "medium")).lower()
        points = _SEVERITY_POINTS.get(severity, 10)
        identifiers = []
        for m in hit.get("matches") or []:
            name = m.get("name", "?")
            offset = m.get("offset", -1)
            identifiers.append("%s@%d" % (name, offset))
        evidence = "YARA rule '%s' matched: %s" % (
            rule,
            ", ".join(identifiers) if identifiers else "no string instances",
        )
        detail = "Severity %s via YARA signature scan (static-only)." % severity
        signals.append(
            {"points": points, "evidence": evidence, "detail": detail}
        )
    return signals
