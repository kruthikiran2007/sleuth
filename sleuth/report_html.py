"""Sleuth HTML report renderer — Feature 4.

Renders a Sleuth report dict (as produced by ``sleuth.analyze.analyze()``)
as a fully self-contained HTML document: inline CSS only, zero external
requests (no CDN, no web fonts, no images, no JavaScript).

Security contract: EVERYTHING that is user- or file-controlled (paths,
signal evidence/details, secret previews, YARA rule names, APK package
names, permissions, indicator strings, section names, ...) goes through
``html.escape`` before being interpolated into the markup. The pipeline
already redacts secret values before they reach this module; this module
guarantees the markup itself cannot be broken out of.
"""

import html

from sleuth import __version__

_VERDICT_COLORS = {
    "CLEAN": "#1a7f37",              # green
    "SUSPICIOUS": "#9a6700",         # amber
    "MALICIOUS-LOOKING": "#b42318",  # red
}

_LIMITATIONS_NOTE = (
    "Static analysis only \u2014 verdicts are triage aids, not proof. "
    "Sleuth never executes the target."
)

_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
       Helvetica, Arial, sans-serif; color: #1f2328; background: #f6f8fa;
       margin: 0; padding: 24px; }
.wrap { max-width: 900px; margin: 0 auto; background: #fff;
        border: 1px solid #d0d7de; border-radius: 8px; padding: 28px 32px; }
header { border-bottom: 2px solid #d0d7de; padding-bottom: 12px;
         margin-bottom: 20px; display: flex; align-items: baseline;
         justify-content: space-between; flex-wrap: wrap; gap: 8px; }
h1 { font-size: 24px; margin: 0; }
h1 .version { font-size: 13px; color: #57606a; font-weight: normal;
              margin-left: 8px; }
h2 { font-size: 17px; margin-top: 26px; border-bottom: 1px solid #eaeef2;
     padding-bottom: 6px; }
.badge { display: inline-block; padding: 4px 14px; border-radius: 999px;
         color: #fff; font-weight: bold; font-size: 15px; letter-spacing: .5px; }
.summary { color: #57606a; font-size: 14px; margin: 10px 0 4px; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px;
        margin-top: 8px; }
th, td { border: 1px solid #d0d7de; padding: 7px 10px; text-align: left;
         vertical-align: top; }
th { background: #f6f8fa; }
td.num { text-align: right; white-space: nowrap; }
ul { font-size: 13.5px; }
code { background: #f6f8fa; padding: 1px 5px; border-radius: 4px;
       font-size: 12.5px; }
.pill { display: inline-block; padding: 1px 10px; border-radius: 999px;
        font-size: 12px; font-weight: bold; color: #fff; }
.pill.on { background: #1a7f37; }
.pill.off { background: #b42318; }
.dangerous { color: #b42318; font-weight: bold; }
.empty { color: #57606a; font-style: italic; }
footer { margin-top: 28px; padding-top: 12px; border-top: 1px solid #d0d7de;
         color: #57606a; font-size: 12.5px; }
"""


def _esc(value):
    """Escape anything user/file-controlled for safe HTML output."""
    return html.escape(str(value), quote=True)


def _fmt_size(n):
    try:
        return "%d bytes (%s)" % (int(n), _human_size(int(n)))
    except (TypeError, ValueError):
        return _esc(n)


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit)
        n /= 1020.0
    return "%d GB" % n


def render_html(report):
    """Render a Sleuth report dict as a complete HTML document string."""
    verdict = str(report.get("verdict", "UNKNOWN"))
    color = _VERDICT_COLORS.get(verdict, "#57606a")

    parts = []
    add = parts.append

    add("<!DOCTYPE html>")
    add('<html lang="en">')
    add("<head>")
    add('<meta charset="utf-8">')
    add("<title>Sleuth report: %s</title>" % _esc(report.get("path", "")))
    add("<style>%s</style>" % _CSS)
    add("</head>")
    add("<body>")
    add('<div class="wrap">')

    # Header.
    add('<header><h1>Sleuth<span class="version">v%s</span></h1>'
        % _esc(__version__))
    add('<span class="badge" style="background:%s">%s</span></header>'
        % (color, _esc(verdict)))

    # Summary line.
    add('<p class="summary">type: %s &nbsp;|&nbsp; size: %s '
        '&nbsp;|&nbsp; strings: %s &nbsp;|&nbsp; score: %s</p>' % (
            _esc(report.get("file_type", "unknown")),
            _fmt_size(report.get("size", 0)),
            _esc(report.get("string_count", 0)),
            _esc(report.get("score", 0)),
        ))
    add("<p class=\"summary\">target: <code>%s</code></p>"
        % _esc(report.get("path", "")))

    # Signals table.
    signals = report.get("signals") or []
    add("<h2>Signals (%d)</h2>" % len(signals))
    if signals:
        add("<table><tr><th>Points</th><th>Evidence</th><th>Detail</th></tr>")
        for sig in signals:
            add("<tr><td class=\"num\">%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(sig.get("points", "")),
                _esc(sig.get("evidence", "")),
                _esc(sig.get("detail", "")),
            ))
        add("</table>")
    else:
        add('<p class="empty">No signals raised.</p>')

    # Secrets — redacted previews only (already redacted upstream).
    secrets = report.get("secrets") or []
    add("<h2>Secrets (%d)</h2>" % len(secrets))
    if secrets:
        add("<ul>")
        for hit in secrets:
            add("<li><strong>%s</strong>: <code>%s</code> "
                "(string #%s)</li>" % (
                    _esc(hit.get("type", "")),
                    _esc(hit.get("preview", "")),
                    _esc(hit.get("line", "")),
                ))
        add("</ul>")
    else:
        add('<p class="empty">No secrets found.</p>')

    # Optional YARA matches.
    yara_matches = report.get("yara_matches") or []
    if yara_matches:
        add("<h2>YARA matches (%d)</h2>" % len(yara_matches))
        add("<table><tr><th>Rule</th><th>Severity</th>"
            "<th>Matches</th></tr>")
        for m in yara_matches:
            matches = m.get("matches", [])
            count = len(matches) if isinstance(matches, list) else matches
            add("<tr><td>%s</td><td>%s</td><td class=\"num\">%s</td></tr>"
                % (_esc(m.get("rule", "")),
                   _esc(m.get("severity", "")),
                   _esc(count)))
        add("</table>")

    # Optional capa capabilities (MITRE ATT&CK).
    capa = report.get("capa") or {}
    if capa.get("available"):
        caps = capa.get("capabilities") or []
        add("<h2>capa capabilities (%d)</h2>" % len(caps))
        if caps:
            add("<table><tr><th>Capability</th><th>ATT&amp;CK</th>"
                "<th>Points</th></tr>")
            for cap in caps:
                ids = [a.get("id") for a in cap.get("attack", [])
                       if a.get("id")]
                techs = [a.get("technique") for a in cap.get("attack", [])
                         if a.get("technique")]
                tag = ", ".join(ids)
                if techs:
                    tag += " (%s)" % ", ".join(techs)
                add("<tr><td>%s</td><td>%s</td><td class=\"num\">%s</td></tr>"
                    % (_esc(cap.get("name", "")),
                       _esc(tag or "no ATT&CK map"),
                       _esc(cap.get("points", ""))))
            add("</table>")
        else:
            add('<p class="empty">No capabilities matched.</p>')
    elif capa.get("reason"):
        add("<h2>capa</h2>")
        add('<p class="empty">%s</p>' % _esc(capa["reason"]))

    # Optional threat intel.
    intel = report.get("intel") or {}
    if intel.get("available") or intel.get("reason"):
        add("<h2>Threat intel (MalwareBazaar)</h2>")
        if intel.get("known"):
            add('<p><span class="pill off">KNOWN MALWARE</span></p>')
            add("<p>family: <code>%s</code></p>"
                % _esc(intel.get("family") or "unknown"))
            tags = intel.get("tags") or []
            if tags:
                add("<p>tags: %s</p>" % _esc(", ".join(tags[:10])))
            if intel.get("first_seen"):
                add("<p>first seen: %s</p>" % _esc(intel["first_seen"]))
        elif intel.get("available"):
            add('<p class="empty">Hash not found — unknown sample.</p>')
        else:
            add('<p class="empty">%s</p>' % _esc(intel.get("reason", "")))
        if intel.get("sha256"):
            add("<p class=\"summary\">sha256: <code>%s</code></p>"
                % _esc(intel["sha256"]))

    # Optional disassembly excerpt.
    disasm = report.get("disasm")
    if isinstance(disasm, dict) and disasm.get("available"):
        insns = disasm.get("instructions") or []
        add("<h2>Disassembly excerpt (%s, showing %d of %d)</h2>" % (
            _esc(disasm.get("arch", "?")),
            min(25, len(insns)), len(insns)))
        add("<table><tr><th>Address</th><th>Mnemonic</th>"
            "<th>Operands</th></tr>")
        for insn in insns[:25]:
            add("<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>"
                % (_esc(insn.get("address", "")),
                   _esc(insn.get("mnemonic", "")),
                   _esc(insn.get("op_str", ""))))
        add("</table>")

    # Optional APK details.
    apk = report.get("apk")
    if isinstance(apk, dict) and apk:
        add("<h2>APK details</h2>")
        add("<p>package: <code>%s</code></p>"
            % _esc(apk.get("package", "unknown")))
        perms = apk.get("permissions") or []
        dangerous = set(apk.get("dangerous_permissions") or [])
        add("<h3>Permissions (%d)</h3>" % len(perms))
        if perms:
            add("<ul>")
            for p in perms:
                cls = ' class="dangerous"' if p in dangerous else ""
                add("<li%s>%s</li>" % (cls, _esc(p)))
            add("</ul>")
        else:
            add('<p class="empty">No permissions listed.</p>')
        risky = apk.get("risky_combos") or []
        add("<h3>Risky permission combinations</h3>")
        if risky:
            add("<ul>")
            for combo in risky:
                if isinstance(combo, (list, tuple)):
                    combo = " + ".join(combo)
                add("<li>%s</li>" % _esc(combo))
            add("</ul>")
        else:
            add('<p class="empty">None detected.</p>')
        debuggable = apk.get("debuggable")
        pill = ('<span class="pill on">ON</span>'
                if debuggable else '<span class="pill off">OFF</span>')
        add("<p>debuggable: %s</p>" % pill)

    # Anatomy: sections table + mitigations.
    anatomy = report.get("anatomy") or {}
    add("<h2>Anatomy</h2>")
    sections = anatomy.get("sections") or []
    if sections:
        add("<table><tr><th>Section</th><th>Size</th><th>Entropy</th></tr>")
        for sec in sections:
            add("<tr><td>%s</td><td class=\"num\">%s</td>"
                "<td class=\"num\">%s</td></tr>" % (
                    _esc(sec.get("name", "")),
                    _esc(sec.get("size", "")),
                    _esc(sec.get("entropy", "")),
                ))
        add("</table>")
    else:
        reason = anatomy.get("reason")
        add('<p class="empty">%s</p>'
            % (_esc(reason) if reason else "No section data available."))
    mitigations = anatomy.get("mitigations") or {}
    if mitigations:
        add("<h3>Mitigations</h3>")
        add("<table><tr><th>Mitigation</th><th>Status</th></tr>")
        for name, enabled in mitigations.items():
            pill = ('<span class="pill on">ON</span>'
                    if enabled else '<span class="pill off">OFF</span>')
            add("<tr><td>%s</td><td>%s</td></tr>"
                % (_esc(name), pill))
        add("</table>")

    # Indicators.
    indicators = report.get("indicators") or {}
    add("<h2>Indicators</h2>")
    ips = indicators.get("ips") or []
    urls = indicators.get("urls") or []
    add("<h3>IP addresses (%d)</h3>" % len(ips))
    if ips:
        add("<ul>")
        for ip in ips:
            add("<li><code>%s</code></li>" % _esc(ip))
        add("</ul>")
    else:
        add('<p class="empty">None found.</p>')
    add("<h3>URLs (%d)</h3>" % len(urls))
    if urls:
        add("<ul>")
        for url in urls:
            add("<li><code>%s</code></li>" % _esc(url))
        add("</ul>")
    else:
        add('<p class="empty">None found.</p>')

    # Code signature (Authenticode, PE only).
    sig = report.get("signature") or {}
    if sig.get("available"):
        add("<h2>Code signature</h2>")
        if sig.get("signed"):
            add('<p>signed: <span class="pill on">YES</span> '
                "(certificate table present, %s bytes; chain validity "
                "NOT checked)</p>" % _esc(sig.get("cert_size", 0)))
            if sig.get("signer_hint"):
                add("<p>signer hint: <code>%s</code> (heuristic, not "
                    "verified)</p>" % _esc(sig["signer_hint"]))
        else:
            add('<p>signed: <span class="pill off">NO</span></p>')
        if sig.get("company_name"):
            add("<p>version-info CompanyName: <code>%s</code></p>"
                % _esc(sig["company_name"]))
    elif sig.get("reason"):
        add("<h2>Code signature</h2>")
        add('<p class="empty">%s</p>' % _esc(sig["reason"]))

    # IOCs (leads for review, not verdicts).
    iocs = report.get("iocs") or {}
    if iocs:
        add("<h2>Indicators of Compromise</h2>")
        add('<p class="empty">Leads for a human analyst — not verdicts.</p>')
        for ioc_type in sorted(iocs):
            items = iocs[ioc_type]
            add("<h3>%s (%d)</h3>" % (_esc(ioc_type), len(items)))
            add("<table><tr><th>Value</th><th>Confidence</th>"
                "<th>Note</th></tr>")
            for item in items[:25]:
                add("<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
                    % (_esc(item.get("value", "")),
                       _esc(item.get("confidence", "")),
                       _esc(item.get("note", ""))))
            add("</table>")

    # Footer with honest limitations note.
    add("<footer>%s Report generated by Sleuth v%s. %s</footer>" % (
        _esc(report.get("path", "")),
        _esc(__version__),
        _LIMITATIONS_NOTE,
    ))

    add("</div>")
    add("</body>")
    add("</html>")
    return "\n".join(parts)


def write_html(report, out_path):
    """Write the HTML report for *report* to *out_path* (utf-8).

    Returns *out_path*.
    """
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
    return out_path


def render_scan_html(scan):
    """Render a folder-scan dict (from sleuth.folder_scan) as HTML."""
    parts = []
    add = parts.append

    add("<!DOCTYPE html>")
    add('<html lang="en">')
    add("<head>")
    add('<meta charset="utf-8">')
    add("<title>Sleuth folder scan: %s</title>" % _esc(scan.get("folder", "")))
    add("<style>%s</style>" % _CSS)
    add("</head>")
    add("<body>")
    add('<div class="wrap">')
    add('<header><h1>Sleuth folder scan<span class="version">v%s</span></h1>'
        % _esc(__version__))
    add("</header>")
    add("<p class=\"summary\">folder: <code>%s</code></p>"
        % _esc(scan.get("folder", "")))
    counts = scan.get("counts", {})
    add('<p class="summary">%s files triaged — %s clean, %s suspicious, '
        '%s malicious-looking</p>' % (
            _esc(counts.get("scanned", 0)), _esc(counts.get("clean", 0)),
            _esc(counts.get("suspicious", 0)),
            _esc(counts.get("malicious_looking", 0))))

    files = scan.get("files") or []
    add("<h2>Files (worst-first)</h2>")
    if files:
        add("<table><tr><th>Score</th><th>Verdict</th><th>Type</th>"
            "<th>File</th></tr>")
        for entry in files:
            color = _VERDICT_COLORS.get(entry.get("verdict", ""),
                                        "#57606a")
            add("<tr><td class=\"num\">%s</td>"
                "<td><span class=\"badge\" style=\"background:%s\">%s</span></td>"
                "<td>%s</td><td><code>%s</code></td></tr>" % (
                    _esc(entry.get("score", "")),
                    color, _esc(entry.get("verdict", "")),
                    _esc(entry.get("file_type", "")),
                    _esc(entry.get("path", ""))))
        add("</table>")
    else:
        add('<p class="empty">No executable-ish files found.</p>')

    skipped = scan.get("skipped") or {}
    if sum(skipped.values()):
        add("<h2>Skipped</h2>")
        add("<ul>")
        for key in ("too_large", "symlink_outside", "not_executable",
                    "error"):
            add("<li>%s: %s</li>" % (_esc(key), _esc(skipped.get(key, 0))))
        add("</ul>")

    add("<footer>%s</footer>" % _LIMITATIONS_NOTE)
    add("</div>")
    add("</body>")
    add("</html>")
    return "\n".join(parts)


def write_scan_html(scan, out_path):
    """Write the HTML folder-scan report to *out_path* (utf-8)."""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_scan_html(scan))
    return out_path


def render_diff_html(diff):
    """Render a diff dict (from sleuth.diff) as a self-contained HTML page."""
    parts = []
    add = parts.append

    add("<!DOCTYPE html>")
    add('<html lang="en">')
    add("<head>")
    add('<meta charset="utf-8">')
    add("<title>Sleuth diff: %s vs %s</title>" % (
        _esc(diff.get("old_path", "")), _esc(diff.get("new_path", ""))))
    add("<style>%s</style>" % _CSS)
    add("</head>")
    add("<body>")
    add('<div class="wrap">')

    add('<header><h1>Sleuth diff<span class="version">v%s</span></h1></header>'
        % _esc(__version__))
    add("<p class=\"summary\">old: <code>%s</code><br>new: <code>%s</code></p>"
        % (_esc(diff.get("old_path", "")), _esc(diff.get("new_path", ""))))
    add("<p class=\"summary\">verdict: %s (%s) &rarr; %s (%s)</p>" % (
        _esc(diff.get("old_verdict", "?")), _esc(diff.get("old_score", 0)),
        _esc(diff.get("new_verdict", "?")), _esc(diff.get("new_score", 0))))
    add("<h2>Summary</h2>")
    add("<p>%s</p>" % _esc(diff.get("summary", "")))

    def _list_section(title, items, prefix):
        add("<h2>%s (%d)</h2>" % (_esc(title), len(items)))
        if items:
            add("<ul>")
            for item in items[:50]:
                add("<li>%s <code>%s</code></li>" % (prefix, _esc(item)))
            add("</ul>")
        else:
            add('<p class="empty">None.</p>')

    _list_section("Imports added", diff.get("imports_added") or [], "+")
    _list_section("Imports removed", diff.get("imports_removed") or [], "&minus;")
    _list_section("Sections added", diff.get("sections_added") or [], "+")
    _list_section("Sections removed", diff.get("sections_removed") or [], "&minus;")

    changed = diff.get("sections_changed") or []
    add("<h2>Sections changed (%d)</h2>" % len(changed))
    if changed:
        add("<table><tr><th>Section</th><th>Size &Delta;</th>"
            "<th>Entropy &Delta;</th></tr>")
        for ch in changed:
            add("<tr><td>%s</td><td class=\"num\">%+d</td>"
                "<td class=\"num\">%+.2f</td></tr>" % (
                    _esc(ch.get("name", "")),
                    ch.get("size_delta", 0),
                    ch.get("entropy_delta", 0.0)))
        add("</table>")
    else:
        add('<p class="empty">None.</p>')

    _list_section("New secrets", diff.get("secrets_added") or [], "+")
    _list_section("New YARA hits", diff.get("yara_added") or [], "+")
    _list_section("Gone YARA hits", diff.get("yara_removed") or [], "&minus;")

    mit = diff.get("mitigations_changed") or {}
    add("<h2>Mitigations changed (%d)</h2>" % len(mit))
    if mit:
        add("<table><tr><th>Mitigation</th><th>Old</th><th>New</th></tr>")
        for key in sorted(mit):
            add("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(key), _esc(mit[key].get("old", "")),
                _esc(mit[key].get("new", ""))))
        add("</table>")
    else:
        add('<p class="empty">None.</p>')

    add("<footer>Report generated by Sleuth v%s. %s</footer>" % (
        _esc(__version__), _LIMITATIONS_NOTE))
    add("</div>")
    add("</body>")
    add("</html>")
    return "\n".join(parts)


def write_diff_html(diff, out_path):
    """Write the HTML diff report for *diff* to *out_path* (utf-8)."""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_diff_html(diff))
    return out_path
