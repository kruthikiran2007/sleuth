"""capa capability detection with MITRE ATT&CK mapping for Sleuth.

Runs FLARE capa's static analysis (in-process, pefile/elffile backends —
no disassembly engine needed) against Sleuth's own compact ruleset in
``rules/capa/``. Every matched capability carries its MITRE ATT&CK
technique ID and name, e.g. "T1055 Process Injection".

The target is only read from disk — never executed, loaded, or emulated.

Graceful degradation:
- If ``capa`` (flare-capa) is not installed, ``CAPA_AVAILABLE`` is False,
  ``status()`` says so, and ``scan_file()`` returns
  ``{"available": False, "reason": ...}``. Nothing raises.
- If the rules directory is missing/unusable, same graceful result.
- Only PE and ELF targets are analyzed; other types return
  ``{"available": False, "reason": "unsupported file type for capa"}``.

Two capa 9.x quirks are worked around here (documented inline):
1. ``capa.rules`` references ``capa.rules.cache`` without importing it, so
   we import ``capa.rules.cache`` first.
2. ATT&CK metadata lives inside ``rule.meta["att&ck"]`` as strings like
   ``"Defense Evasion::Process Injection [T1055]"``.
"""

import os
import pathlib

try:
    # Quirk 1: capa 9.x forgets to import its own cache submodule.
    import capa.rules.cache  # noqa: F401
    import capa.rules
    from capa import loader
    from capa.capabilities.common import find_file_capabilities

    CAPA_AVAILABLE = True
except Exception:
    CAPA_AVAILABLE = False

# Absolute path to Sleuth's compact capa ruleset (source tree or install).
from ._paths import capa_rules_dir as _resolve_capa_rules_dir

RULES_DIR = _resolve_capa_rules_dir()

# Cache: rules_dir -> compiled RuleSet (or None on failure).
_ruleset_cache = {}

# ATT&CK tactics we treat as high-confidence malicious, with the points
# each matched capability contributes to the Sleuth verdict.
_HIGH_TACTICS = {
    "credential access",
    "defense evasion",
    "persistence",
    "privilege escalation",
    "command and control",
    "exfiltration",
    "impact",
}
_MEDIUM_TACTICS = {
    "execution",
    "collection",
    "discovery",
    "lateral movement",
}
_HIGH_POINTS = 15
_MEDIUM_POINTS = 8
_LOW_POINTS = 4


def status():
    """One-line human-readable readiness string."""
    if not CAPA_AVAILABLE:
        return "flare-capa not installed — run: pip install flare-capa"
    rules = _load_ruleset()
    if rules is None:
        return "capa ready (0 rules loaded — check rules/capa/)"
    count = len(rules.rules) if hasattr(rules, "rules") else 0
    return "capa ready (%d rules loaded)" % count


def _load_ruleset(rules_dir=RULES_DIR):
    """Compile Sleuth's capa ruleset (cached). Returns None on any failure."""
    if not CAPA_AVAILABLE:
        return None
    key = os.path.abspath(rules_dir)
    if key in _ruleset_cache:
        return _ruleset_cache[key]
    ruleset = None
    try:
        if os.path.isdir(rules_dir):
            ruleset = capa.rules.get_rules(
                [pathlib.Path(rules_dir)], enable_cache=False
            )
    except Exception:
        ruleset = None
    _ruleset_cache[key] = ruleset
    return ruleset


def _parse_attack(spec):
    """Parse an ATT&CK spec string into a dict.

    Input looks like "Defense Evasion::Process Injection [T1055]" or
    "Collection::Input Capture::Keylogging [T1056.001]". Returns
    {"tactic":..., "technique":..., "subtechnique":..., "id":...}.
    Unparseable input yields empty strings (never raises).
    """
    tactic = technique = subtechnique = ident = ""
    if not isinstance(spec, str):
        return {"tactic": tactic, "technique": technique,
                "subtechnique": subtechnique, "id": ident}
    try:
        text = spec
        # Split off the trailing "[Txxxx]" identifier.
        head, sep, tail = text.rpartition(" ")
        if sep and tail.startswith("[") and tail.endswith("]"):
            ident = tail[1:-1]
        else:
            head = text
        parts = [p.strip() for p in head.split("::")]
        if len(parts) > 0:
            tactic = parts[0]
        if len(parts) > 1:
            technique = parts[1]
        if len(parts) > 2:
            subtechnique = parts[2]
    except Exception:
        pass
    return {
        "tactic": tactic,
        "technique": technique,
        "subtechnique": subtechnique,
        "id": ident,
    }


def _points_for(attack_entries):
    """Verdict points for a capability from its ATT&CK tactics."""
    tactics = {a.get("tactic", "").lower() for a in attack_entries}
    if tactics & _HIGH_TACTICS:
        return _HIGH_POINTS
    if tactics & _MEDIUM_TACTICS:
        return _MEDIUM_POINTS
    return _LOW_POINTS


def scan_file(path, rules_dir=RULES_DIR):
    """Run capa on *path* and return a structured result.

    Returns a dict::

        {"available": bool,
         "reason": str (only when unavailable),
         "capabilities": [
             {"name": str, "namespace": str,
              "attack": [{"tactic","technique","subtechnique","id"}],
              "points": int},
         ]}

    Only PE and ELF files are analyzed (checked via magic bytes here, so
    this function does not depend on sleuth.detect). Never raises.
    """
    if not CAPA_AVAILABLE:
        return {
            "available": False,
            "reason": "flare-capa not installed — run: pip install flare-capa",
            "capabilities": [],
        }
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError as exc:
        return {"available": False, "reason": "cannot read file: %s" % exc,
                "capabilities": []}
    if magic.startswith(b"MZ"):
        fmt = "pe"
    elif magic.startswith(b"\x7fELF"):
        fmt = "elf"
    else:
        return {"available": False,
                "reason": "capa supports PE and ELF targets only",
                "capabilities": []}

    ruleset = _load_ruleset(rules_dir)
    if ruleset is None:
        return {"available": False,
                "reason": "could not load capa rules from %s" % rules_dir,
                "capabilities": []}
    try:
        rules_by_name = (
            ruleset.rules
            if isinstance(ruleset.rules, dict)
            else {r.name: r for r in ruleset.rules}
        )
        extractors = loader.get_file_extractors(pathlib.Path(path), fmt)
        if not extractors:
            return {"available": False,
                    "reason": "no capa extractor for this file",
                    "capabilities": []}
        caps = find_file_capabilities(ruleset, extractors[0], {})
        out = []
        for name in caps.matches:
            rule = rules_by_name.get(name)
            meta = rule.meta if rule is not None else {}
            attack = [_parse_attack(s) for s in meta.get("att&ck", []) or []]
            out.append(
                {
                    "name": name,
                    "namespace": meta.get("namespace", ""),
                    "attack": attack,
                    "points": _points_for(attack),
                }
            )
        # Deterministic order: highest points first, then name.
        out.sort(key=lambda c: (-c["points"], c["name"]))
        return {"available": True, "capabilities": out}
    except Exception as exc:
        return {"available": False,
                "reason": "capa analysis failed: %s" % exc,
                "capabilities": []}


def capa_signals(scan_result):
    """Convert scan_file() output to Sleuth signal dicts.

    Each signal: {"points","evidence","detail"}. Evidence cites the
    capability name plus ATT&CK technique IDs.
    """
    signals = []
    for cap in (scan_result or {}).get("capabilities", []):
        ids = [a["id"] for a in cap.get("attack", []) if a.get("id")]
        techs = [a["technique"] for a in cap.get("attack", [])
                 if a.get("technique")]
        label = "%s%s" % (
            ", ".join(ids),
            (" (%s)" % ", ".join(techs)) if techs else "",
        )
        signals.append(
            {
                "points": cap.get("points", _LOW_POINTS),
                "evidence": "capa capability '%s'%s" % (
                    cap.get("name", "?"),
                    (" [%s]" % label) if label else "",
                ),
                "detail": "Capability detected by capa static analysis, "
                          "mapped to MITRE ATT&CK.",
            }
        )
    return signals
