"""Sleuth MCP server: expose the static analyzer as MCP tools.

This module wraps Sleuth's read-only pipeline as Model Context Protocol
tools so an AI agent can inspect binaries without ever executing them.

Safety rules (shared with the rest of Sleuth):
- The target file is opened for reading only. It is NEVER executed.
- Files over ``sleuth.detect.MAX_FILE_SIZE`` (200 MB) are refused.
- Secrets are always redacted; only previews leave this module.
- Every tool catches its own exceptions and returns an error dict.
- Only ``threat_intel`` touches the network (hash lookup); it degrades
  gracefully offline.

The plain tool functions below are importable and testable WITHOUT
the ``mcp`` package installed -- they never reference FastMCP. The server
wiring (``build_server`` / ``main``) needs ``mcp``; without it,
``build_server()`` raises ``RuntimeError`` and the CLI exits with code 2.
"""

import json
import sys

from . import analyze as analyze_mod
from . import detect
from . import secrets as secrets_mod
from . import strings as strings_mod

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # mcp not installed: tools still work, server does not
    FastMCP = None

MCP_AVAILABLE = FastMCP is not None

INSTALL_HINT = "pip install mcp  (then re-run)"


def _size_gate(path):
    """Enforce the 200MB size gate. Returns (ok, size_or_error_dict)."""
    ok, size = detect.check_size_ok(path)
    if not ok:
        return False, {
            "ok": False,
            "error": "refusing file of %d bytes (limit %d bytes)"
            % (size, detect.MAX_FILE_SIZE),
        }
    return True, size


def tool_analyze_file(path: str) -> dict:
    """Run the full Sleuth pipeline on a file (static, read-only).

    Returns {"ok": True, "report": {...}} with a JSON-serializable report:
    file type, size, verdict, score, evidence-cited signals, secrets
    (redacted), network indicators, and binary anatomy.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        report = analyze_mod.analyze(path)
        json.dumps(report)  # prove it is JSON-serializable
        return {"ok": True, "report": report}
    except Exception as exc:  # never let an exception cross the tool boundary
        return {"ok": False, "error": str(exc)}


def tool_get_strings(path: str, limit: int = 200) -> dict:
    """Extract printable strings from a file (static, read-only).

    Returns {"ok": True, "strings": [...], "truncated": bool}.
    ``truncated`` is True when more than ``limit`` strings exist.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        limit = max(0, int(limit))
        with open(path, "rb") as f:
            data = f.read()
        all_strings = strings_mod.extract_strings(data)
        return {
            "ok": True,
            "strings": all_strings[:limit],
            "truncated": len(all_strings) > limit,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_scan_secrets(path: str) -> dict:
    """Scan a file for known secret formats (static, read-only).

    Returns {"ok": True, "findings": [...]}; each finding carries a
    REDACTED preview (never the full secret), its type, and line number.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        with open(path, "rb") as f:
            data = f.read()
        text = "\n".join(strings_mod.extract_strings(data))
        findings = secrets_mod.scan_secrets(text)
        return {"ok": True, "findings": findings}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_yara_scan(path: str) -> dict:
    """Scan a file with YARA rules (static, read-only).

    Returns {"ok": True, "available": bool, "matches": [...]}.
    When the ``sleuth.yara_scan`` module (or yara itself) is not
    available, ``available`` is False with a status message -- never a crash.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        try:
            from . import yara_scan
        except ImportError:
            return {
                "ok": True,
                "available": False,
                "matches": [],
                "status": "sleuth.yara_scan module not available",
            }
        if not getattr(yara_scan, "AVAILABLE", True):
            return {
                "ok": True,
                "available": False,
                "matches": [],
                "status": getattr(
                    yara_scan, "STATUS", "yara engine not available"
                ),
            }
        scan_fn = getattr(yara_scan, "scan_file", None) or getattr(
            yara_scan, "scan", None
        )
        if scan_fn is None:
            return {
                "ok": True,
                "available": False,
                "matches": [],
                "status": "sleuth.yara_scan has no scan entry point",
            }
        matches = scan_fn(path)
        return {"ok": True, "available": True, "matches": list(matches)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_apk_info(path: str) -> dict:
    """Parse Android APK metadata (static, read-only ZIP inspection).

    Returns {"ok": True, "apk": {...}}. For non-APK files the apk dict is
    returned as-is (with ``available`` False) by the parser.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        try:
            from . import apk
        except ImportError:
            return {
                "ok": True,
                "apk": {
                    "available": False,
                    "status": "sleuth.apk module not available",
                },
            }
        info = apk.analyze_apk(path)
        if not isinstance(info, dict):
            return {
                "ok": False,
                "error": "sleuth.apk.analyze_apk returned a non-dict",
            }
        return {"ok": True, "apk": info}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_capa_scan(path: str) -> dict:
    """Detect capabilities with MITRE ATT&CK mapping (static, read-only).

    Returns {"ok": True, "available": bool, "capabilities": [...]}.
    PE and ELF targets only; graceful when flare-capa is missing.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        try:
            from . import capa_scan
        except ImportError:
            return {"ok": True, "available": False, "capabilities": [],
                    "status": "sleuth.capa_scan module not available"}
        result = capa_scan.scan_file(path)
        json.dumps(result)  # prove JSON-serializable
        return {"ok": True, **result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_threat_intel(path: str) -> dict:
    """Look up a file's SHA256 on MalwareBazaar (hash only, read-only).

    Returns {"ok": True, ...lookup dict...}. This is the only tool that
    touches the network; offline it reports unavailable and never fails.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        try:
            from . import threat_intel
        except ImportError:
            return {"ok": False, "error": "sleuth.threat_intel not available"}
        result = threat_intel.lookup(path)
        json.dumps(result)
        return {"ok": True, **result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_diff_binaries(old_path: str, new_path: str) -> dict:
    """Compare two binaries: imports/sections/secrets/YARA deltas.

    Supply-chain check — "did this update sneak in something new?"
    Returns {"ok": True, "diff": {...}} (JSON-serializable).
    """
    try:
        for path in (old_path, new_path):
            allowed, gate = _size_gate(path)
            if not allowed:
                return gate
        try:
            from . import diff as diff_mod
        except ImportError:
            return {"ok": False, "error": "sleuth.diff not available"}
        result = diff_mod.diff_files(old_path, new_path)
        json.dumps(result)
        return {"ok": True, "diff": result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tool_disassemble(path: str, count: int = 200) -> dict:
    """Disassemble the entry-point region (x86/x64 PE/ELF, static).

    Returns {"ok": True, ...disassembly dict...} with instructions and
    honestly-labeled weak indicators. Graceful when capstone is missing.
    """
    try:
        allowed, gate = _size_gate(path)
        if not allowed:
            return gate
        try:
            from . import disasm as disasm_mod
            from . import detect as detect_mod
        except ImportError:
            return {"ok": False, "error": "sleuth.disasm not available"}
        result = disasm_mod.disassemble_file(
            path, detect_mod.detect_type(path), count=int(count))
        json.dumps(result)
        return {"ok": True, **result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


_TOOL_REGISTRATIONS = [
    ("analyze_file", tool_analyze_file),
    ("get_strings", tool_get_strings),
    ("scan_secrets", tool_scan_secrets),
    ("yara_scan", tool_yara_scan),
    ("apk_info", tool_apk_info),
    ("capa_scan", tool_capa_scan),
    ("threat_intel", tool_threat_intel),
    ("diff_binaries", tool_diff_binaries),
    ("disassemble", tool_disassemble),
]


def build_server():
    """Build the FastMCP server with all nine Sleuth tools registered.

    Raises RuntimeError with the install hint when the ``mcp`` package
    is not installed.
    """
    if not MCP_AVAILABLE or FastMCP is None:
        raise RuntimeError(INSTALL_HINT)
    server = FastMCP("sleuth")
    for name, func in _TOOL_REGISTRATIONS:
        server.tool(name=name)(func)
    return server


def main():
    """Run the Sleuth MCP server over stdio.

    ``python -m sleuth.mcp_server`` lands here.
    """
    try:
        server = build_server()
    except RuntimeError:
        print(INSTALL_HINT, file=sys.stderr)
        sys.exit(2)
    server.run()


if __name__ == "__main__":
    main()
