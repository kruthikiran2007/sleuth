"""Sleuth command-line interface.

Commands:
    sleuth analyze <path> [--json] [--html report.html] [--no-intel] [--disasm]
                                     Full pipeline: detect, strings, secrets,
                                     anatomy, YARA, APK, capa, threat intel,
                                     verdict (+ optional disassembly).
    sleuth strings <path>            Print printable strings in the file.
    sleuth secrets <path>            Scan for leaked secrets only.
    sleuth yara <path>               YARA signature scan only.
    sleuth capa <path>               capa capability detection (MITRE ATT&CK).
    sleuth intel <path>              MalwareBazaar known-malware lookup.
    sleuth diff <old> <new> [--json] [--html diff.html]
                                     Compare two binaries (supply-chain check).
    sleuth disasm <path> [--count N] Disassemble entry-point region (x86/x64).
    sleuth scan <folder> [--json] [--html report.html] [--verbose]
                                     Triage every executable-ish file in a
                                     folder, worst-first summary.
    sleuth iocs <path> [--json]      Extract indicators of compromise.
    sleuth gen-yara <path> [-o rule.yar]
                                     Auto-generate a YARA rule from the file's
                                     most distinctive strings (self-tested).

Sleuth never executes the target. All analysis is read-only and static.
Exit codes: 0 = ok, 1 = intake/analysis error, 2 = bad CLI usage.
"""

import argparse
import os
import sys

from . import detect
from . import strings as strings_mod
from . import secrets as secrets_mod
from .analyze import analyze, format_report


def _intake(path):
    """Shared intake checks. Returns (ok, message)."""
    if not os.path.isfile(path):
        return False, "no such file: %s" % path
    ok, size = detect.check_size_ok(path)
    if not ok:
        return False, "refusing file of %d bytes (limit %d)" % (
            size, detect.MAX_FILE_SIZE)
    return True, ""


def cmd_analyze(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        report = analyze(args.path, include_intel=not args.no_intel,
                         include_disasm=args.disasm)
    except (ValueError, FileNotFoundError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.html:
        from . import report_html
        try:
            out = report_html.write_html(report, args.html)
        except Exception as exc:
            print("error writing HTML: %s" % exc, file=sys.stderr)
            return 1
        print(format_report(report, as_json=args.json))
        print("HTML report written to %s" % out)
        return 0
    print(format_report(report, as_json=args.json))
    return 0


def cmd_strings(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    with open(args.path, "rb") as f:
        data = f.read()
    for s in strings_mod.extract_strings(data):
        print(s)
    return 0


def cmd_secrets(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    with open(args.path, "rb") as f:
        data = f.read()
    text = "\n".join(strings_mod.extract_strings(data))
    hits = secrets_mod.scan_secrets(text)
    if not hits:
        print("No known secret formats found.")
        return 0
    for h in hits:
        print("%s at line %d (preview %s)" % (h["type"], h["line"], h["preview"]))
    return 0


def cmd_yara(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        from . import yara_scan
    except ImportError:
        print("error: yara_scan module missing", file=sys.stderr)
        return 1
    print(yara_scan.status())
    matches = yara_scan.scan_file(args.path)
    if not matches:
        print("No YARA rules matched.")
        return 0
    for m in matches:
        print("[%s] %s" % (m.get("severity", "?"), m.get("rule", "?")))
        for hit in m.get("matches", [])[:5]:
            print("    %s @ offset %d: %s" % (
                hit.get("name", "?"), hit.get("offset", -1),
                hit.get("preview", "")))
    return 0


def cmd_capa(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        from . import capa_scan
    except ImportError:
        print("error: capa_scan module missing", file=sys.stderr)
        return 1
    print(capa_scan.status())
    result = capa_scan.scan_file(args.path)
    if not result.get("available"):
        print("capa unavailable: %s" % result.get("reason", "unknown"))
        return 0
    caps = result.get("capabilities", [])
    if not caps:
        print("No capabilities matched.")
        return 0
    for cap in caps:
        ids = [a.get("id") for a in cap.get("attack", []) if a.get("id")]
        techs = [a.get("technique") for a in cap.get("attack", [])
                 if a.get("technique")]
        tag = ", ".join(ids)
        if techs:
            tag += " (%s)" % ", ".join(techs)
        print("[%s] %s (+%d pts)" % (tag or "no ATT&CK map",
                                     cap.get("name", "?"),
                                     cap.get("points", 0)))
    return 0


def cmd_intel(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        from . import threat_intel
    except ImportError:
        print("error: threat_intel module missing", file=sys.stderr)
        return 1
    result = threat_intel.lookup(args.path)
    print("sha256: %s" % result.get("sha256", "?"))
    if not result.get("available"):
        print("threat intel unavailable: %s" % result.get("reason", "unknown"))
        return 0
    if result.get("known"):
        print("KNOWN MALWARE on MalwareBazaar")
        print("  family: %s" % (result.get("family") or "unknown"))
        if result.get("tags"):
            print("  tags: %s" % ", ".join(result["tags"][:10]))
        if result.get("first_seen"):
            print("  first seen: %s" % result["first_seen"])
    else:
        print("hash not found on MalwareBazaar (unknown sample)")
    return 0


def cmd_diff(args):
    for label, path in (("old", args.old), ("new", args.new)):
        ok, msg = _intake(path)
        if not ok:
            print("error (%s): %s" % (label, msg), file=sys.stderr)
            return 1
    try:
        from . import diff as diff_mod
    except ImportError:
        print("error: diff module missing", file=sys.stderr)
        return 1
    try:
        result = diff_mod.diff_files(args.old, args.new)
    except (ValueError, FileNotFoundError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.html:
        from . import report_html
        try:
            out = report_html.write_diff_html(result, args.html)
        except Exception as exc:
            print("error writing HTML: %s" % exc, file=sys.stderr)
            return 1
        print("HTML diff report written to %s" % out)
    if args.json:
        import json
        print(json.dumps(result, indent=2))
    else:
        print(_format_diff(result))
    return 0


def _format_diff(diff):
    lines = [
        "Sleuth diff: %s -> %s" % (diff["old_path"], diff["new_path"]),
        "  verdict: %s (%d) -> %s (%d)" % (
            diff["old_verdict"], diff["old_score"],
            diff["new_verdict"], diff["new_score"]),
        "",
        "  " + diff["summary"],
        "",
    ]
    if diff["imports_added"]:
        lines.append("  Imports added:")
        for name in diff["imports_added"][:20]:
            lines.append("    + %s" % name)
        lines.append("")
    if diff["imports_removed"]:
        lines.append("  Imports removed:")
        for name in diff["imports_removed"][:20]:
            lines.append("    - %s" % name)
        lines.append("")
    if diff["sections_added"] or diff["sections_removed"]:
        lines.append("  Sections added: %s" % ", ".join(diff["sections_added"]))
        lines.append("  Sections removed: %s" % ", ".join(diff["sections_removed"]))
        lines.append("")
    for ch in diff["sections_changed"]:
        lines.append("  Section '%s': size %+d, entropy %+.2f" % (
            ch["name"], ch["size_delta"], ch["entropy_delta"]))
    if diff["sections_changed"]:
        lines.append("")
    if diff["secrets_added"]:
        lines.append("  New secrets: %s" % ", ".join(diff["secrets_added"][:10]))
        lines.append("")
    if diff["yara_added"] or diff["yara_removed"]:
        lines.append("  YARA added: %s" % ", ".join(diff["yara_added"]))
        lines.append("  YARA removed: %s" % ", ".join(diff["yara_removed"]))
        lines.append("")
    for key, change in diff["mitigations_changed"].items():
        lines.append("  Mitigation '%s': %s -> %s" % (
            key, change["old"], change["new"]))
    if diff["mitigations_changed"]:
        lines.append("")
    return "\n".join(lines)


def cmd_disasm(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        from . import disasm as disasm_mod
        from . import detect
    except ImportError:
        print("error: disasm module missing", file=sys.stderr)
        return 1
    result = disasm_mod.disassemble_file(args.path, detect.detect_type(args.path),
                                         count=args.count)
    if not result.get("available"):
        print("disassembly unavailable: %s" % result.get("reason", "unknown"))
        return 0
    print("arch: %s | %d instructions (entry-point excerpt)" % (
        result.get("arch", "?"), result.get("count", 0)))
    for insn in result.get("instructions", []):
        print("  %s  %-10s %s" % (insn.get("address", "?"),
                                  insn.get("mnemonic", "?"),
                                  insn.get("op_str", "")))
    weak = result.get("weak_signals", [])
    if weak:
        print("weak indicators:")
        for sig in weak:
            print("  [+%d] %s -- %s" % (sig["points"], sig["evidence"],
                                        sig["detail"]))
    return 0


def cmd_scan(args):
    try:
        from . import folder_scan
    except ImportError:
        print("error: folder_scan module missing", file=sys.stderr)
        return 1
    try:
        scan = folder_scan.scan_folder(args.folder,
                                        include_intel=args.intel,
                                        verbose=args.verbose)
    except FileNotFoundError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.html:
        from . import report_html
        try:
            out = report_html.write_scan_html(scan, args.html)
        except Exception as exc:
            print("error writing HTML: %s" % exc, file=sys.stderr)
            return 1
        print(folder_scan.format_scan(scan, verbose=args.verbose))
        print("HTML report written to %s" % out)
        return 0
    if args.json:
        import json
        print(json.dumps(scan, indent=2))
        return 0
    print(folder_scan.format_scan(scan, verbose=args.verbose))
    return 0


def cmd_iocs(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        from . import iocs as iocs_mod
    except ImportError:
        print("error: iocs module missing", file=sys.stderr)
        return 1
    with open(args.path, "rb") as f:
        data = f.read()
    found = iocs_mod.extract_iocs(strings_mod.extract_strings(data))
    if args.json:
        import json
        print(json.dumps(found, indent=2))
        return 0
    if not found:
        print("No IOCs extracted.")
        return 0
    print("IOCs (leads for review, not verdicts):")
    for ioc_type in sorted(found):
        print("  %s:" % ioc_type)
        for item in found[ioc_type][:15]:
            print("    [%s] %s -- %s" % (
                item.get("confidence", "?"), item.get("value", "?"),
                item.get("note", "")))
    return 0


def cmd_gen_yara(args):
    ok, msg = _intake(args.path)
    if not ok:
        print("error: %s" % msg, file=sys.stderr)
        return 1
    try:
        from . import yara_gen
    except ImportError:
        print("error: yara_gen module missing", file=sys.stderr)
        return 1
    result = yara_gen.generate_rule(args.path, output_path=args.output)
    if result.get("rule_text") and not args.output:
        print(result["rule_text"])
    if result["ok"]:
        print("OK: %s" % result["reason"])
        if result.get("written_to"):
            print("rule written to %s" % result["written_to"])
        return 0
    print("error: %s" % result["reason"], file=sys.stderr)
    if result.get("rule_text"):
        print(result["rule_text"])
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sleuth",
        description="Static binary/app inspector. Never executes the target.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Full analysis with verdict")
    p_analyze.add_argument("path", help="File to inspect (read-only)")
    p_analyze.add_argument("--json", action="store_true", help="JSON output")
    p_analyze.add_argument("--html", metavar="FILE",
                           help="Also write a self-contained HTML report to FILE")
    p_analyze.add_argument("--no-intel", action="store_true",
                           help="Skip the MalwareBazaar lookup (fully offline)")
    p_analyze.add_argument("--disasm", action="store_true",
                           help="Append an entry-point disassembly excerpt")
    p_analyze.set_defaults(func=cmd_analyze)

    p_strings = sub.add_parser("strings", help="Extract printable strings")
    p_strings.add_argument("path", help="File to inspect (read-only)")
    p_strings.set_defaults(func=cmd_strings)

    p_secrets = sub.add_parser("secrets", help="Scan for leaked secrets")
    p_secrets.add_argument("path", help="File to inspect (read-only)")
    p_secrets.set_defaults(func=cmd_secrets)

    p_yara = sub.add_parser("yara", help="YARA signature scan only")
    p_yara.add_argument("path", help="File to inspect (read-only)")
    p_yara.set_defaults(func=cmd_yara)

    p_capa = sub.add_parser("capa", help="capa capability detection (ATT&CK)")
    p_capa.add_argument("path", help="File to inspect (read-only)")
    p_capa.set_defaults(func=cmd_capa)

    p_intel = sub.add_parser("intel", help="MalwareBazaar known-malware lookup")
    p_intel.add_argument("path", help="File to inspect (read-only)")
    p_intel.set_defaults(func=cmd_intel)

    p_diff = sub.add_parser("diff", help="Compare two binaries")
    p_diff.add_argument("old", help="Baseline binary (read-only)")
    p_diff.add_argument("new", help="Updated binary (read-only)")
    p_diff.add_argument("--json", action="store_true", help="JSON output")
    p_diff.add_argument("--html", metavar="FILE",
                        help="Write a self-contained HTML diff report to FILE")
    p_diff.set_defaults(func=cmd_diff)

    p_disasm = sub.add_parser("disasm", help="Disassemble entry point (x86/x64)")
    p_disasm.add_argument("path", help="File to inspect (read-only)")
    p_disasm.add_argument("--count", type=int, default=200,
                          help="Max instructions to show (default 200)")
    p_disasm.set_defaults(func=cmd_disasm)

    p_scan = sub.add_parser("scan", help="Triage every executable-ish file "
                                        "in a folder (worst-first)")
    p_scan.add_argument("folder", help="Directory to scan (read-only)")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.add_argument("--html", metavar="FILE",
                        help="Also write a self-contained HTML report to FILE")
    p_scan.add_argument("--verbose", action="store_true",
                        help="Show per-file signals in the text summary")
    p_scan.add_argument("--intel", action="store_true",
                        help="Enable MalwareBazaar lookups per file "
                             "(slow; off by default in scan mode)")
    p_scan.set_defaults(func=cmd_scan)

    p_iocs = sub.add_parser("iocs", help="Extract indicators of compromise")
    p_iocs.add_argument("path", help="File to inspect (read-only)")
    p_iocs.add_argument("--json", action="store_true", help="JSON output")
    p_iocs.set_defaults(func=cmd_iocs)

    p_gen = sub.add_parser("gen-yara", help="Auto-generate a YARA rule from "
                                           "a file's distinctive strings")
    p_gen.add_argument("path", help="File to learn from (read-only)")
    p_gen.add_argument("-o", "--output", metavar="FILE",
                       help="Write the rule to FILE (default: print only)")
    p_gen.set_defaults(func=cmd_gen_yara)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
