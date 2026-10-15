"""Analysis orchestrator: runs the full Sleuth pipeline on one file.

Pipeline: size gate -> type detection -> strings -> secrets -> indicators ->
binary anatomy (ELF/PE only) -> heuristics -> verdict.

Everything is read-only. The target is opened for reading, never executed.
"""

import os

from . import detect
from . import strings as strings_mod
from . import secrets as secrets_mod
from . import elf_info
from . import pe_info
from . import heuristics

# Optional feature modules: imported lazily so a broken/missing extra never
# breaks the core pipeline.
def _optional(name):
    try:
        return __import__("sleuth." + name, fromlist=["*"])
    except Exception:
        return None


def analyze(path, include_intel=True, include_disasm=False):
    """Run the full pipeline on *path*. Returns a report dict.

    Raises FileNotFoundError / ValueError (too large) for intake problems.

    *include_intel*: when True (default), query MalwareBazaar for the file's
    SHA256. This is the only step that touches the network; it degrades
    gracefully offline. Pass False to stay fully offline.
    *include_disasm*: when True, append an entry-point disassembly excerpt.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError("no such file: %s" % path)

    ok, size = detect.check_size_ok(path)
    if not ok:
        raise ValueError(
            "refusing file of %d bytes (limit %d bytes)"
            % (size, detect.MAX_FILE_SIZE)
        )

    with open(path, "rb") as f:
        data = f.read()

    file_type = detect.detect_type(path)

    extracted = strings_mod.extract_strings(data)
    text = "\n".join(extracted)
    secret_hits = secrets_mod.scan_secrets(text)
    indicators = strings_mod.find_indicators(extracted)

    anatomy = {"available": False, "reason": "no binary parser for this type"}
    if file_type == "elf":
        anatomy = elf_info.analyze_elf(data)
    elif file_type == "pe":
        anatomy = pe_info.analyze_pe(data)

    result = heuristics.evaluate(anatomy, secret_hits, indicators, file_type,
                                 strings=extracted)

    # Feature: YARA signature scan (graceful if yara-python is missing).
    yara_scan = _optional("yara_scan")
    yara_matches = []
    if yara_scan is not None:
        try:
            yara_matches = yara_scan.scan_file(path) or []
        except Exception:
            yara_matches = []

    # Feature: APK deep-dive (auto-detected by file type).
    apk_mod = _optional("apk")
    apk_info = None
    if file_type == "apk" and apk_mod is not None:
        try:
            apk_info = apk_mod.analyze_apk(path)
        except Exception:
            apk_info = {"available": False, "reason": "apk analysis failed"}

    # Feature: capa capability detection (PE/ELF only, graceful if missing).
    capa_mod = _optional("capa_scan")
    capa_result = {"available": False, "reason": "capa module missing",
                   "capabilities": []}
    if capa_mod is not None and file_type in ("pe", "elf"):
        try:
            capa_result = capa_mod.scan_file(path) or capa_result
        except Exception:
            pass

    # Feature: MalwareBazaar threat-intel lookup (only network step;
    # skipped with include_intel=False, always offline-safe).
    intel_mod = _optional("threat_intel")
    intel_result = {"available": False,
                    "reason": "skipped (--no-intel)",
                    "known": False}
    if intel_mod is not None and include_intel:
        try:
            intel_result = intel_mod.lookup(path) or intel_result
        except Exception:
            intel_result = {"available": False,
                            "reason": "threat intel lookup failed",
                            "known": False}

    # Feature: entry-point disassembly excerpt (opt-in via --disasm).
    disasm_mod = _optional("disasm")
    disasm_result = None
    if disasm_mod is not None and include_disasm:
        try:
            disasm_result = disasm_mod.disassemble_file(path, file_type)
        except Exception:
            disasm_result = {"available": False,
                             "reason": "disassembly failed"}

    # Merge feature signals into the verdict (score re-derived honestly).
    extra = []
    if yara_scan is not None and yara_matches:
        try:
            extra.extend(yara_scan.yara_signals(yara_matches))
        except Exception:
            pass
    if apk_info and apk_info.get("available"):
        extra.extend(apk_info.get("signals", []))
    if capa_mod is not None and capa_result.get("available"):
        try:
            extra.extend(capa_mod.capa_signals(capa_result))
        except Exception:
            pass
    if intel_mod is not None and intel_result.get("known"):
        try:
            extra.extend(intel_mod.intel_signal(intel_result))
        except Exception:
            pass
    if disasm_result and disasm_result.get("available"):
        extra.extend(disasm_result.get("weak_signals", []))
    # Feature: Authenticode signature check (PE only; impersonation
    # heuristic signals fold into the verdict, honestly cited).
    sig_mod = _optional("signature")
    sig_result = {"available": False,
                  "reason": "signature module missing",
                  "signed": False, "signals": []}
    if sig_mod is not None:
        try:
            sig_result = sig_mod.check_signature(path) or sig_result
        except Exception:
            sig_result = {"available": False,
                          "reason": "signature check failed",
                          "signed": False, "signals": []}
    if sig_result.get("available"):
        extra.extend(sig_result.get("signals", []))
    if extra:
        heuristics.apply_extra_signals(result, extra)

    # Feature: IOC extraction (informational only — leads for a human,
    # never scored into the verdict).
    iocs_mod = _optional("iocs")
    ioc_result = {}
    if iocs_mod is not None:
        try:
            ioc_result = iocs_mod.extract_iocs(extracted)
        except Exception:
            ioc_result = {}

    result.update(
        {
            "path": path,
            "size": size,
            "file_type": file_type,
            "string_count": len(extracted),
            "secrets": secret_hits,
            "indicators": indicators,
            "anatomy": anatomy,
            "yara_matches": yara_matches,
            "apk": apk_info,
            "capa": capa_result,
            "intel": intel_result,
            "disasm": disasm_result,
            "signature": sig_result,
            "iocs": ioc_result,
        }
    )
    return result


def format_report(report, as_json=False):
    """Render a report dict as human-readable text (or JSON)."""
    if as_json:
        import json

        return json.dumps(report, indent=2)

    lines = [
        "Sleuth report: %s" % report["path"],
        "  type: %s | size: %d bytes | strings: %d"
        % (report["file_type"], report["size"], report["string_count"]),
        "",
        "  VERDICT: %s (score %d)"
        % (report["verdict"], report["score"]),
        "",
    ]

    if report["signals"]:
        lines.append("  Signals (each cites its evidence):")
        for sig in report["signals"]:
            lines.append(
                "    [+%d] %s -- %s" % (sig["points"], sig["evidence"], sig["detail"])
            )
        lines.append("")
    else:
        lines.append("  No suspicious signals found.")
        lines.append("")

    anatomy = report["anatomy"]
    if anatomy.get("available"):
        lines.append("  Sections:")
        for sec in anatomy["sections"]:
            lines.append(
                "    %-20s size=%-8d entropy=%s"
                % (sec["name"], sec["size"], sec["entropy"])
            )
        lines.append("")
        lines.append("  Mitigations:")
        for name, enabled in anatomy["mitigations"].items():
            lines.append("    %s: %s" % (name, "ON" if enabled else "OFF"))
        lines.append("")
    else:
        lines.append("  Anatomy: %s" % anatomy.get("reason", "n/a"))
        lines.append("")

    if report["indicators"]["ips"] or report["indicators"]["urls"]:
        lines.append("  Network indicators (review manually, not verdicts):")
        for ip in report["indicators"]["ips"][:10]:
            lines.append("    IP: %s" % ip)
        for url in report["indicators"]["urls"][:10]:
            lines.append("    URL: %s" % url)
        lines.append("")

    yara_matches = report.get("yara_matches") or []
    if yara_matches:
        lines.append("  YARA matches:")
        for m in yara_matches:
            lines.append("    [%s] %s (%d strings)" % (
                m.get("severity", "?"), m.get("rule", "?"),
                len(m.get("matches", []))))
        lines.append("")

    capa = report.get("capa") or {}
    if capa.get("available"):
        lines.append("  capa capabilities (MITRE ATT&CK):")
        for cap in capa.get("capabilities", []):
            ids = [a.get("id") for a in cap.get("attack", []) if a.get("id")]
            techs = [a.get("technique") for a in cap.get("attack", [])
                     if a.get("technique")]
            tag = ", ".join(ids)
            if techs:
                tag += " (%s)" % ", ".join(techs)
            lines.append("    [%s] %s" % (tag or "no ATT&CK map",
                                          cap.get("name", "?")))
        lines.append("")
    elif capa.get("reason"):
        lines.append("  capa: %s" % capa["reason"])
        lines.append("")

    intel = report.get("intel") or {}
    if intel.get("available"):
        if intel.get("known"):
            lines.append("  Threat intel: KNOWN MALWARE on MalwareBazaar")
            lines.append("    family: %s" % (intel.get("family") or "unknown"))
            if intel.get("tags"):
                lines.append("    tags: %s" % ", ".join(intel["tags"][:8]))
            if intel.get("first_seen"):
                lines.append("    first seen: %s" % intel["first_seen"])
        else:
            lines.append("  Threat intel: hash not found on MalwareBazaar "
                         "(unknown sample)")
        lines.append("")
    elif intel.get("reason"):
        lines.append("  Threat intel: %s" % intel["reason"])
        lines.append("")

    disasm = report.get("disasm")
    if isinstance(disasm, dict) and disasm.get("available"):
        lines.append("  Disassembly excerpt (%s, %d instructions):"
                     % (disasm.get("arch", "?"), disasm.get("count", 0)))
        for insn in disasm.get("instructions", [])[:10]:
            lines.append("    %s  %-10s %s" % (
                insn.get("address", "?"), insn.get("mnemonic", "?"),
                insn.get("op_str", "")))
        lines.append("")

    sig = report.get("signature") or {}
    if sig.get("available"):
        lines.append("  Code signature (Authenticode):")
        if sig.get("signed"):
            lines.append("    signed: YES (certificate table present, "
                         "%d bytes)" % sig.get("cert_size", 0))
            if sig.get("signer_hint"):
                lines.append("    signer hint: %s (heuristic, not verified)"
                             % sig["signer_hint"])
        else:
            lines.append("    signed: NO")
        if sig.get("company_name"):
            lines.append("    version-info CompanyName: %s"
                         % sig["company_name"])
        lines.append("    note: presence of a certificate table is reported; "
                     "chain validity is NOT checked")
        lines.append("")
    elif sig.get("reason"):
        lines.append("  Code signature: %s" % sig["reason"])
        lines.append("")

    iocs = report.get("iocs") or {}
    if iocs:
        lines.append("  Indicators of Compromise (leads for review, "
                     "not verdicts):")
        for ioc_type in sorted(iocs):
            items = iocs[ioc_type]
            lines.append("    %s (%d):" % (ioc_type, len(items)))
            for item in items[:8]:
                lines.append("      [%s] %s -- %s" % (
                    item.get("confidence", "?"), item.get("value", "?"),
                    item.get("note", "")))
        lines.append("")

    apk = report.get("apk")
    if apk and apk.get("available"):
        lines.append("  APK: %s" % apk.get("package", "?"))
        dp = apk.get("dangerous_permissions") or []
        lines.append("    permissions: %d (%d dangerous)" % (
            len(apk.get("permissions", [])), len(dp)))
        for perm in dp:
            lines.append("      DANGEROUS: %s" % perm)
        for combo in apk.get("risky_combos", []):
            lines.append("      RISKY COMBO: %s -- %s" % (
                ", ".join(combo.get("combo", [])), combo.get("label", "")))
        if apk.get("debuggable"):
            lines.append("      debuggable=true (do not ship like this)")
        lines.append("")

    return "\n".join(lines)
