"""Folder scan mode: triage every executable-ish file in a directory.

The "security guard" use case: point Sleuth at a downloads folder, a USB
stick, or an extracted archive and get a ranked worst-first summary —
which files deserve attention, and which are clean.

Safety rules (non-negotiable):
- Files over 200 MB are skipped (existing size gate).
- Symlinks pointing *outside* the scanned folder are skipped (no escaping
  the scan root via link tricks). Symlinked directories outside the root
  are not descended into.
- Nothing is ever executed. Every file is only read.
- Threat-intel lookups are OFF by default in scan mode (one network query
  per file would be slow and rude to abuse.ch); the per-file detail still
  notes that intel was skipped.

A file counts as "executable-ish" if its extension is on the candidate
list OR its magic bytes look executable (MZ/ELF/Mach-O/ZIP-APK). Scripts
(.ps1, .js, .py, ...) are included because droppers love them.
"""

import os

from . import detect
from .analyze import analyze

# Extensions worth triaging (lowercased, with dot).
_EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".apk", ".jar",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".py", ".pyw", ".sh",
    ".bat", ".cmd", ".elf", ".so", ".dylib", ".bin", ".msi",
}

# Magic bytes that mark an executable container even with a weird name.
_BIN_MAGICS = (
    b"MZ",                 # PE / DOS executable
    b"\x7fELF",            # ELF
    b"\xfe\xed\xfa\xce",   # Mach-O 32
    b"\xfe\xed\xfa\xcf",   # Mach-O 64
    b"\xca\xfe\xba\xbe",   # Mach-O fat
    b"PK\x03\x04",         # ZIP (covers APK/JAR)
)


def is_candidate(path):
    """True if *path* looks executable-ish by extension or magic bytes."""
    ext = os.path.splitext(path)[1].lower()
    if ext in _EXEC_EXTS:
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head.startswith(_BIN_MAGICS)


def _inside_root(resolved, root):
    """True if *resolved* (absolute, symlink-resolved) is inside *root*."""
    return resolved == root or resolved.startswith(root + os.sep)


def scan_folder(folder, include_intel=False, verbose=False):
    """Recursively triage *folder*. Returns a summary dict::

        {
          "folder": str,            # absolute scan root
          "files": [                # worst-first by score
            {"path": str, "file_type": str, "verdict": str, "score": int,
             "signals": [...]},     # signals only when verbose=True
          ],
          "counts": {"scanned": n, "clean": n, "suspicious": n,
                     "malicious_looking": n},
          "skipped": {"too_large": n, "symlink_outside": n,
                      "not_executable": n, "error": n},
        }

    Never raises for per-file problems (they are counted in "skipped").
    Raises FileNotFoundError if *folder* is not a directory.
    """
    root = os.path.abspath(folder)
    if not os.path.isdir(root):
        raise FileNotFoundError("not a directory: %s" % folder)

    files = []
    skipped = {"too_large": 0, "symlink_outside": 0, "not_executable": 0,
               "error": 0}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune symlinked dirs that escape the root.
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                target = os.path.realpath(full)
                if not _inside_root(target, root):
                    dirnames.remove(d)
                    skipped["symlink_outside"] += 1

        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                if os.path.islink(full):
                    target = os.path.realpath(full)
                    if not (_inside_root(target, root)
                            and os.path.isfile(target)):
                        skipped["symlink_outside"] += 1
                        continue
                if not is_candidate(full):
                    skipped["not_executable"] += 1
                    continue
                ok, _size = detect.check_size_ok(full)
                if not ok:
                    skipped["too_large"] += 1
                    continue
                report = analyze(full, include_intel=include_intel,
                                 include_disasm=False)
            except Exception:
                skipped["error"] += 1
                continue

            entry = {
                "path": full,
                "file_type": report.get("file_type", "unknown"),
                "verdict": report.get("verdict", "UNKNOWN"),
                "score": int(report.get("score", 0)),
            }
            if verbose:
                entry["signals"] = report.get("signals", [])
            files.append(entry)

    files.sort(key=lambda e: -e["score"])

    counts = {"scanned": len(files), "clean": 0, "suspicious": 0,
              "malicious_looking": 0}
    for entry in files:
        if entry["verdict"] == "MALICIOUS-LOOKING":
            counts["malicious_looking"] += 1
        elif entry["verdict"] == "SUSPICIOUS":
            counts["suspicious"] += 1
        else:
            counts["clean"] += 1

    return {"folder": root, "files": files, "counts": counts,
            "skipped": skipped}


def format_scan(scan, verbose=False):
    """Render a scan summary dict as human-readable text (worst-first)."""
    lines = [
        "Sleuth folder scan: %s" % scan["folder"],
        "  %d files triaged (%d clean, %d suspicious, %d malicious-looking)"
        % (scan["counts"]["scanned"], scan["counts"]["clean"],
           scan["counts"]["suspicious"], scan["counts"]["malicious_looking"]),
        "",
    ]
    files = scan["files"]
    if files:
        lines.append("  %5s  %-16s  %-8s  %s"
                     % ("SCORE", "VERDICT", "TYPE", "FILE"))
        for entry in files:
            lines.append("  %5d  %-16s  %-8s  %s" % (
                entry["score"], entry["verdict"], entry["file_type"],
                entry["path"]))
            if verbose:
                for sig in entry.get("signals", []):
                    lines.append("           [+%d] %s" % (
                        sig.get("points", 0), sig.get("evidence", "")))
        lines.append("")
    else:
        lines.append("  No executable-ish files found.")
        lines.append("")
    skipped = scan["skipped"]
    total_skipped = sum(skipped.values())
    if total_skipped:
        lines.append("  Skipped: %d too large, %d symlink-outside, "
                     "%d not executable, %d errors" % (
                         skipped["too_large"], skipped["symlink_outside"],
                         skipped["not_executable"], skipped["error"]))
    return "\n".join(lines)
