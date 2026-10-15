"""Binary diff for Sleuth: compare two binaries for supply-chain checks.

``diff_files(old_path, new_path)`` answers: "did this update sneak in
something new?" It compares imports, sections, secrets, YARA matches,
mitigations, and version strings between two binaries.

Both inputs are analyzed with the standard Sleuth pipeline (threat-intel
lookup skipped — diffing is about binary changes, not reputation).
Everything is read-only; neither file is executed.

Output is a plain JSON-serializable dict plus a human-readable summary.
Use ``sleuth diff old.bin new.bin [--json]`` or feed the dict to
``report_html.render_diff_html``.
"""

from . import analyze as analyze_mod
from . import heuristics


def _flatten_imports(anatomy):
    """Collect imported symbol names into a set, whatever the format."""
    imports = (anatomy or {}).get("imports", [])
    flat = set()
    if isinstance(imports, dict):  # PE: {dll: [funcs]}
        for funcs in imports.values():
            flat.update(funcs)
    else:  # ELF: [names]
        flat.update(imports)
    return {str(x) for x in flat}


def _sections_map(anatomy):
    """Map section name -> (size, entropy) for diffing."""
    out = {}
    for sec in (anatomy or {}).get("sections", []):
        try:
            entropy = float(sec.get("entropy", 0) or 0)
        except (TypeError, ValueError):
            entropy = 0.0
        out[str(sec.get("name", "?"))] = (sec.get("size", 0), entropy)
    return out


def _secret_keys(secrets):
    """Identify secrets by (type, preview) — previews are already redacted."""
    return {
        "%s:%s" % (s.get("type", "?"), s.get("preview", "?"))
        for s in secrets or []
    }


def _yara_names(matches):
    return {m.get("rule", "?") for m in matches or []}


def diff_reports(old_report, new_report):
    """Diff two analyze() report dicts. Returns a JSON-serializable dict."""
    old_imports = _flatten_imports(old_report.get("anatomy"))
    new_imports = _flatten_imports(new_report.get("anatomy"))

    old_secs = _sections_map(old_report.get("anatomy"))
    new_secs = _sections_map(new_report.get("anatomy"))

    sections_changed = []
    for name in sorted(set(old_secs) & set(new_secs)):
        old_size, old_ent = old_secs[name]
        new_size, new_ent = new_secs[name]
        if old_size != new_size or abs(old_ent - new_ent) >= 0.5:
            sections_changed.append(
                {
                    "name": name,
                    "size_delta": new_size - old_size,
                    "entropy_delta": round(new_ent - old_ent, 2),
                }
            )

    old_sec = _secret_keys(old_report.get("secrets"))
    new_sec = _secret_keys(new_report.get("secrets"))
    old_yara = _yara_names(old_report.get("yara_matches"))
    new_yara = _yara_names(new_report.get("yara_matches"))

    old_mit = (old_report.get("anatomy") or {}).get("mitigations", {})
    new_mit = (new_report.get("anatomy") or {}).get("mitigations", {})
    mitigations_changed = {}
    for key in sorted(set(old_mit) | set(new_mit)):
        if old_mit.get(key) != new_mit.get(key):
            mitigations_changed[key] = {
                "old": bool(old_mit.get(key)),
                "new": bool(new_mit.get(key)),
            }

    diff = {
        "old_path": old_report.get("path", ""),
        "new_path": new_report.get("path", ""),
        "old_verdict": old_report.get("verdict", "?"),
        "new_verdict": new_report.get("verdict", "?"),
        "old_score": old_report.get("score", 0),
        "new_score": new_report.get("score", 0),
        "imports_added": sorted(new_imports - old_imports),
        "imports_removed": sorted(old_imports - new_imports),
        "sections_added": sorted(set(new_secs) - set(old_secs)),
        "sections_removed": sorted(set(old_secs) - set(new_secs)),
        "sections_changed": sections_changed,
        "secrets_added": sorted(new_sec - old_sec),
        "secrets_removed": sorted(old_sec - new_sec),
        "yara_added": sorted(new_yara - old_yara),
        "yara_removed": sorted(old_yara - new_yara),
        "mitigations_changed": mitigations_changed,
    }
    diff["summary"] = summarize_diff(diff)
    return diff


def summarize_diff(diff):
    """One-paragraph human summary of a diff dict."""
    bits = []
    ia, ir = diff["imports_added"], diff["imports_removed"]
    if ia:
        bits.append("%d import(s) added (%s)" % (len(ia), ", ".join(ia[:5])))
    if ir:
        bits.append("%d import(s) removed (%s)" % (len(ir), ", ".join(ir[:5])))
    sa, sr = diff["sections_added"], diff["sections_removed"]
    if sa:
        bits.append("sections added: %s" % ", ".join(sa))
    if sr:
        bits.append("sections removed: %s" % ", ".join(sr))
    if diff["sections_changed"]:
        bits.append("%d section(s) changed size/entropy" % len(diff["sections_changed"]))
    if diff["secrets_added"]:
        bits.append("%d new embedded secret(s)" % len(diff["secrets_added"]))
    if diff["yara_added"]:
        bits.append("new YARA hits: %s" % ", ".join(diff["yara_added"]))
    if diff["yara_removed"]:
        bits.append("YARA hits gone: %s" % ", ".join(diff["yara_removed"]))
    if diff["mitigations_changed"]:
        bits.append("mitigations changed: %s" % ", ".join(diff["mitigations_changed"]))
    if diff["old_verdict"] != diff["new_verdict"]:
        bits.append(
            "verdict changed: %s -> %s" % (diff["old_verdict"], diff["new_verdict"])
        )
    if not bits:
        return "No meaningful differences found between the two binaries."
    return "Differences: " + "; ".join(bits) + "."


def diff_files(old_path, new_path):
    """Analyze two binaries and diff them. Returns a diff dict.

    Raises FileNotFoundError / ValueError for intake problems (same as
    analyze). Threat-intel lookup is skipped for both sides.
    """
    old_report = analyze_mod.analyze(old_path, include_intel=False)
    new_report = analyze_mod.analyze(new_path, include_intel=False)
    return diff_reports(old_report, new_report)
