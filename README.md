# 🔍 Sleuth — is this file safe? Answer in 10 seconds.

![tests](https://img.shields.io/badge/tests-228%20passing-brightgreen) ![version](https://img.shields.io/badge/version-0.4.1-blue) ![pypi](https://img.shields.io/pypi/v/sleuth-sec) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

**The security guard for your downloads folder.** Point Sleuth at any suspicious file and get a verdict — **CLEAN / SUSPICIOUS / MALICIOUS-LOOKING** — with evidence cited for every claim. It never runs the file. Ever.

```bash
pip install sleuth-sec
sleuth analyze shady.exe
```

Want everything (YARA + MITRE ATT&CK via capa)? `pip install "sleuth-sec[full]"` —
or see the [Install](#install) section for the manual/zip route.

```bash
$ python -m sleuth.cli analyze shady.exe

  VERDICT: MALICIOUS-LOOKING (score 95)

  Signals (each cites its evidence):
    [+60] KNOWN MALWARE on MalwareBazaar — family: Emotet
    [+20] unsigned binary claims "Microsoft Corporation" identity — no signature
    [+15] [T1055 Process Injection] injects into remote process
```

**🎬 Watch it in action** — 53-second demo, real runs and real verdicts:

https://github.com/kruthikiran2007/sleuth/releases/download/v0.4.1/sleuth-demo.mp4

## Why Sleuth?

| | Sleuth | Deep-RE tools (e.g. REA) | Online scanners |
|---|---|---|---|
| **Answers "is it safe?"** | ✅ verdict in seconds | ❌ explains, doesn't judge | ✅ |
| **Uploads your file** | ❌ never leaves your machine | ❌ local | ⚠️ you upload the file |
| **Setup** | `pip install` | Node + decompiler + MCP setup | account needed |
| **Batch-scan a folder** | ✅ worst-first triage | ❌ | ❌ |
| **Works offline** | ✅ (`--no-intel`) | ✅ | ❌ |

Deep reverse-engineering tools are the *laboratory* — magnificent for investigation down to the instruction level. Sleuth is the *security guard at the door*: ten seconds, evidence-backed verdict, zero friction. Different jobs — and for the "should I run this?" question, the guard is what you reach for.

## Safety

- **Sleuth never executes the target.** Analysis is purely read-only: it reads
  bytes, parses headers, and matches patterns. Nothing is run, loaded, or
  emulated.
- Secrets are **redacted** in output (first 4 chars + `...`) — full keys never
  appear in reports or logs.
- Files over **200 MB** are refused.
- **Network**: the MalwareBazaar hash lookup is the *only* feature that
  touches the network (it sends just the SHA256 — the file never leaves
  your machine). It degrades gracefully offline, and `analyze --no-intel`
  skips it for a fully offline run.

## Install

**Recommended** — from PyPI (after first publish):

```bash
pip install sleuth-sec
sleuth analyze suspicious-file.exe
```

Optional extras:

```bash
pip install "sleuth-sec[full]"   # + yara-python (YARA) + flare-capa (MITRE ATT&CK)
pip install "sleuth-sec[mcp]"    # + MCP server for AI assistants (Claude Code, Cursor)
```

**Alternative** — from the ZIP (manual, no PyPI):

```bash
unzip sleuth-mvp.zip && cd sleuth
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m sleuth.cli analyze suspicious-file.exe
```

`requirements.txt`: `pyelftools`, `pefile`, `yara-python`, `capstone`,
`pytest` (core). `flare-capa` and `mcp<2` are optional extras —
see above.
Heavy/optional ones degrade gracefully: if `pyelftools`/`pefile`/
`yara-python`/`flare-capa`/`capstone` are missing, Sleuth prints a clear
message and continues without that feature — the CLI never crashes.

**Windows notes:** `yara-python` and `capstone` ship wheels, so they
normally just install. `flare-capa` is the heavyweight (~40 packages
including vivisect); if you skip it, capa capabilities are simply skipped
with a note. Everything else works.

## Usage

```bash
# Full analysis with verdict (YARA + APK + capa + threat intel automatic)
python -m sleuth.cli analyze /path/to/file
python -m sleuth.cli analyze /path/to/file --json
python -m sleuth.cli analyze /path/to/file --no-intel      # fully offline
python -m sleuth.cli analyze /path/to/file --disasm        # + disassembly excerpt

# Self-contained HTML report (inline CSS, no external requests)
python -m sleuth.cli analyze /path/to/file --html report.html

# Individual engines
python -m sleuth.cli yara /path/to/file     # YARA signature scan
python -m sleuth.cli capa /path/to/file     # capa capabilities + ATT&CK
python -m sleuth.cli intel /path/to/file    # MalwareBazaar lookup
python -m sleuth.cli disasm /path/to/file --count 50

# Supply-chain check: what changed between two binaries?
python -m sleuth.cli diff old.exe new.exe
python -m sleuth.cli diff old.exe new.exe --html diff.html

# Just the printable strings / secret scan
python -m sleuth.cli strings /path/to/file
python -m sleuth.cli secrets /path/to/file

# Folder scan: triage a whole directory, worst-first
python -m sleuth.cli scan ~/Downloads
python -m sleuth.cli scan ~/Downloads --html scan.html   # shareable report
python -m sleuth.cli scan ~/Downloads --verbose          # per-file signals

# IOC extraction: IPs, URLs, registry paths, wallets, ...
python -m sleuth.cli iocs /path/to/file

# Hunt siblings: auto-generate a YARA rule from a nasty sample
python -m sleuth.cli gen-yara evil.exe -o hunt.yar
# (the rule is compiled and self-tested against its source before writing)

# Run the test suite
python -m pytest tests/ -q
```

APKs are auto-detected: `analyze app.apk` parses the manifest (package,
permissions, dangerous-permission flags, risky combos like SMS-read+send,
`debuggable` flag) and scans `classes.dex` for secrets.

Example:

```
$ python -m sleuth.cli analyze shady.apk
Sleuth report: shady.apk
  type: apk | size: 915 bytes | strings: 17

  VERDICT: MALICIOUS-LOOKING (score 64)

  Signals (each cites its evidence):
    [+10] YARA rule 'upx_packer' matched: $upx_magic@626 -- ...
    [+5] dangerous permission 'android.permission.SEND_SMS' declared
    [+12] risky permission combo: can read and send SMS -- premium-SMS fraud pattern
    ...
```

## MCP server (use Sleuth as AI-assistant tools)

`sleuth/mcp_server.py` exposes Sleuth over MCP (stdio) with nine tools:
`analyze_file`, `get_strings`, `scan_secrets`, `yara_scan`, `apk_info`,
`capa_scan`, `threat_intel`, `diff_binaries`, `disassemble`.
Requires `pip install "mcp<2"` (mcp 2.x removed the `fastmcp` import path).

Claude Code (`~/.claude.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "sleuth": {
      "command": "python",
      "args": ["-m", "sleuth.mcp_server"],
      "cwd": "/path/to/sleuth"
    }
  }
}
```

Cursor: Settings → MCP → Add server → same command/args/cwd.

Then ask your agent: *"Is this file suspicious? Investigate with Sleuth."*

## Verdicts

| Verdict | Meaning |
|---|---|
| `CLEAN` | No suspicious signals found. (Static analysis can't prove safety.) |
| `SUSPICIOUS` | Worth investigating — review each cited signal. |
| `MALICIOUS-LOOKING` | Strong indicators — do not run the file; quarantine it. |

Every signal cites its exact evidence (section name, import name, string,
YARA rule, permission). Sleuth never invents findings — if unsure, it says so.

## Limitations (honest)

- **Static only**: packed/obfuscated binaries hide their true behavior.
  High entropy suggests packing — it is not proof of malice.
- **Heuristics, not proof**: a verdict is a triage aid. Confirm with a
  sandbox or VirusTotal before acting.
- **Regex secrets / YARA**: test keys and docs examples also match; verify hits.
  The starter YARA rules are generic string signatures, not malware code.
- **APK manifest**: only components with explicit `android:exported="true"`
  are listed; implicit export is not inferred. No androguard dependency — a
  minimal built-in AXML parser is used instead (keeps installs painless).
- **No dynamic analysis**: Sleuth never runs code, so runtime behavior
  (what it *does*) is out of scope by design.
- **capa**: uses Sleuth's own compact ruleset (`sleuth/rules/capa/`, 12 rules) —
  not the full Mandiant collection — and the fast pefile/elffile backends
  (no disassembly engine). It is slower than the other engines on large
  binaries; on huge files expect seconds, not milliseconds.
- **Threat intel**: needs internet; offline it reports "unavailable" and the
  analysis continues. Only the SHA256 hash is sent, never the file.
- **Disassembly**: excerpt-only (entry-point region, x86/x64) — a triage
  view, not a full disassembler. Weak-pattern flags are weak by design.
- **Diff**: compares static features; it cannot tell you *why* a vendor
  changed something, only *what* changed.
- **Code signature**: reports *presence* of an Authenticode certificate
  table — it does not validate the chain, expiry, or revocation. An
  unsigned binary is normal for hobby software; it is only suspicious
  when paired with a claimed system identity.
- **IOCs**: extraction is regex-based. Version numbers can look like IPs
  (`5.1.0.0`) — these are downgraded to low confidence and labeled, but
  some noise is unavoidable. IOCs are *leads*, never verdicts.
- **gen-yara**: generated rules catch *siblings* (same strings), not
  *variants* (recompiled/renamed). Review before deploying to production
  hunting.
- **Folder scan**: runs the full pipeline per file (capa included), so
  large folders take a while; threat-intel lookups are off by default in
  scan mode (`--intel` to enable).
- ELF parsing needs `pyelftools`; PE parsing needs `pefile`; YARA needs
  `yara-python`; capa needs `flare-capa`; disassembly needs `capstone` —
  all degrade gracefully when missing.

## Project layout

```
sleuth/
  cli.py          argparse CLI (analyze / strings / secrets / yara / capa /
                  intel / diff / disasm, --html, --no-intel, --disasm)
  analyze.py      pipeline orchestrator + report formatting
  detect.py       magic-byte file-type detection
  strings.py      string extraction, entropy, IP/URL indicators
  secrets.py      leaked-secret regexes with redaction
  elf_info.py     ELF sections / imports / mitigations (pyelftools)
  pe_info.py      PE sections / imports / mitigations (pefile)
  yara_scan.py    YARA signature engine (yara-python, graceful if missing)
  capa_scan.py    capa capability detection + MITRE ATT&CK (flare-capa,
                  graceful if missing; own ruleset in sleuth/rules/capa/)
  threat_intel.py MalwareBazaar SHA256 lookup (stdlib urllib, offline-safe)
  diff.py         binary diff: imports/sections/secrets/YARA deltas
  disasm.py       entry-point disassembly excerpts (capstone, graceful)
  apk.py          APK manifest parsing + dex secret scan (stdlib only)
  signature.py    Authenticode certificate-table check + trusted-identity
                  impersonation heuristic (PE-only, pefile)
  iocs.py         IOC extraction: IPs, URLs/domains, emails, registry paths,
                  file paths, PDB paths, user-agents, BTC/ETH wallets
                  (stdlib regexes, confidence-labeled, informational only)
  yara_gen.py     YARA rule auto-generator from distinctive strings
                  (self-tested: compiles + matches source before writing)
  folder_scan.py  folder triage: worst-first ranked summary of every
                  executable-ish file (size gate, symlink-escape guard)
  mcp_server.py   MCP server: analyze_file, get_strings, scan_secrets,
                  yara_scan, apk_info, capa_scan, threat_intel,
                  diff_binaries, disassemble (needs mcp<2)
  report_html.py  self-contained HTML report + diff renderer + folder-scan
                  renderer
sleuth/rules/     starter YARA ruleset + Sleuth capa ruleset (12 rules)
tests/            pytest suite
SKILL.md          instructions for driving Sleuth as an AI agent
```
