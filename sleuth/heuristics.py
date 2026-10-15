"""Heuristic signals and the final verdict.

Every signal carries the exact evidence behind it (section name, import name,
matched string). The verdict is a weighted score, and the report always says
*why* — Sleuth never invents findings. A high score means "looks malicious,
investigate further", never "this IS malware".

Verdict bands:
    score >= 60  -> MALICIOUS-LOOKING
    score >= 25  -> SUSPICIOUS
    otherwise    -> CLEAN
"""

# Section entropy above this suggests packing/encryption (not proof).
PACKER_ENTROPY_THRESHOLD = 7.5

# Suspicious imports/APIs. Combos (tuples) score higher than single hits.
_SUSPICIOUS_IMPORTS = {
    # Linux / ELF
    "ptrace": ("Anti-debugging API", 15),
    "process_vm_readv": ("Cross-process memory reading", 15),
    "memfd_create": ("Fileless execution primitive", 15),
    # Windows / PE
    "CreateRemoteThread": ("Remote thread injection primitive", 20),
    "WriteProcessMemory": ("Cross-process memory writing", 15),
    "VirtualAlloc": ("Executable memory allocation", 8),
    "VirtualProtect": ("Memory protection tampering", 10),
    "CreateProcess": ("Spawns new processes", 5),
    "WinExec": ("Spawns new processes (legacy API)", 5),
    "ShellExecute": ("Spawns new processes / opens URLs", 5),
    "InternetOpen": ("WinINet networking", 5),
    "URLDownloadToFile": ("Downloads remote files", 15),
    "CryptEncrypt": ("Crypto usage (also seen in ransomware)", 8),
    "SetWindowsHookEx": ("Input hooking primitive", 15),
    "GetAsyncKeyState": ("Keystroke polling primitive", 15),
}

# Combos that are much more suspicious together than apart.
_SUSPICIOUS_COMBOS = [
    (("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"),
     "Classic process-injection chain", 30),
    (("socket", "connect"),
     "Raw socket networking", 10),
]

# Missing hardening mitigations: weak signal, worth noting.
_MITIGATION_NOTES = {
    "nx": ("NX/DEP disabled", 5),
    "pie": ("Not position-independent (no PIE/ASLR)", 5),
    "canary": ("No stack canary", 3),
    "relro": ("No RELRO", 3),
    "dep": ("NX/DEP disabled", 5),
    "aslr": ("Not position-independent (no PIE/ASLR)", 5),
}


def evaluate(anatomy, secrets, indicators, file_type, strings=None):
    """Score the target and produce a verdict.

    *anatomy*: dict from analyze_elf/analyze_pe (may be unavailable).
    *secrets*: list from secrets.scan_secrets.
    *indicators*: dict from strings.find_indicators.
    *file_type*: string from detect.detect_type.
    *strings*: optional list of extracted strings; suspicious API names found
        here (but not confirmed as imports) score as weak unconfirmed signals.

    Returns {"verdict": ..., "score": ..., "signals": [...]} where each
    signal is {"points": n, "evidence": "...", "detail": "..."}.
    """
    signals = []
    strings = strings or []
    string_set = set(strings)

    # 1. High-entropy sections -> possible packer/encryption.
    for section in anatomy.get("sections", []):
        if section["entropy"] >= PACKER_ENTROPY_THRESHOLD and section["size"] > 0:
            signals.append({
                "points": 15,
                "evidence": "section '%s' entropy %.2f" % (
                    section["name"], section["entropy"]),
                "detail": "High entropy suggests packing or encryption "
                          "(not proof of malice)",
            })

    # 2. Suspicious imports.
    flat_imports = _flatten_imports(anatomy)
    for name, (label, points) in _SUSPICIOUS_IMPORTS.items():
        if name in flat_imports:
            signals.append({
                "points": points,
                "evidence": "import '%s'" % name,
                "detail": label,
            })
    for combo, label, points in _SUSPICIOUS_COMBOS:
        if all(c in flat_imports for c in combo):
            signals.append({
                "points": points,
                "evidence": "imports %s" % (", ".join("'%s'" % c for c in combo),),
                "detail": label,
            })

    # 2b. Suspicious API names visible in raw strings but NOT confirmed as
    # imports (e.g. unparseable/packed binaries). Weaker: could be plain text.
    for name, (label, points) in _SUSPICIOUS_IMPORTS.items():
        if name in string_set and name not in flat_imports:
            signals.append({
                "points": max(2, points // 3),
                "evidence": "name '%s' seen in strings (unconfirmed)" % name,
                "detail": label + " — found as text only, not verified as an import",
            })

    # 3. Missing mitigations.
    for name, enabled in anatomy.get("mitigations", {}).items():
        if not enabled and name in _MITIGATION_NOTES:
            label, points = _MITIGATION_NOTES[name]
            signals.append({
                "points": points,
                "evidence": "mitigation '%s' absent" % name,
                "detail": label + " (weakening signal only)",
            })

    # 4. Embedded secrets.
    for finding in secrets:
        signals.append({
            "points": 10,
            "evidence": "secret type '%s' at line %d (preview %s)" % (
                finding["type"], finding["line"], finding["preview"]),
            "detail": "Embedded credential — leak risk; verify it is not a test key",
        })

    # 5. Network indicators (weak on their own).
    for ip in indicators.get("ips", [])[:10]:
        signals.append({
            "points": 2,
            "evidence": "hardcoded IP '%s'" % ip,
            "detail": "Indicator only — many benign programs embed IPs",
        })
    for url in indicators.get("urls", [])[:10]:
        signals.append({
            "points": 2,
            "evidence": "hardcoded URL '%s'" % url,
            "detail": "Indicator only — review the destination manually",
        })

    score = sum(s["points"] for s in signals)
    return {"verdict": _verdict_for_score(score), "score": score,
            "signals": signals}


def _verdict_for_score(score):
    if score >= 60:
        return "MALICIOUS-LOOKING"
    if score >= 25:
        return "SUSPICIOUS"
    return "CLEAN"


def apply_extra_signals(result, extra_signals):
    """Merge externally-produced signals (YARA, APK, ...) into a verdict dict.

    Appends *extra_signals* (each {"points","evidence","detail"}) to
    result["signals"], recomputes the score, and re-derives the verdict.
    Returns the same dict.
    """
    result["signals"].extend(extra_signals)
    result["score"] = sum(s["points"] for s in result["signals"])
    result["verdict"] = _verdict_for_score(result["score"])
    return result


def _flatten_imports(anatomy):
    """Collect every imported symbol name into one set, whatever the format."""
    imports = anatomy.get("imports", [])
    flat = set()
    if isinstance(imports, dict):  # PE: {dll: [funcs]}
        for funcs in imports.values():
            flat.update(funcs)
    else:  # ELF: [names]
        flat.update(imports)
    return flat
