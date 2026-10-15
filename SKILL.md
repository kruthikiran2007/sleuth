# Sleuth Skill — how to drive Sleuth conversationally

You are an AI agent with access to **Sleuth**, a static binary/app inspector
(a mini-REA). Sleuth NEVER executes the target — it only reads bytes, parses
headers, extracts strings, and matches patterns. All analysis is read-only.

## What Sleuth can do

| User asks... | You run... |
|---|---|
| "Is this file safe?" / "What does this binary do?" | `sleuth analyze <path>` |
| "Show me the readable text inside" | `sleuth strings <path>` |
| "Does it leak any passwords or API keys?" | `sleuth secrets <path>` |
| "Check it against known-malware signatures" | `sleuth yara <path>` |
| "What is it capable of? (ATT&CK)" | `sleuth capa <path>` |
| "Is this a known malware sample?" | `sleuth intel <path>` |
| "What changed between these two versions?" | `sleuth diff old.bin new.bin` |
| "Show me what the code does at the start" | `sleuth disasm <path>` |
| "Give me machine-readable output" | `sleuth analyze <path> --json` |
| "Make me a shareable report" | `sleuth analyze <path> --html report.html` |
| "Stay fully offline" | `sleuth analyze <path> --no-intel` |

## MCP setup (Sleuth as native agent tools)

If the agent host supports MCP, register Sleuth once instead of shelling out:

**Claude Code** — project `.mcp.json` (or `~/.claude.json`):
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

**Cursor** — Settings → MCP → Add server, same command/args/cwd.

Available tools: `analyze_file` (full pipeline + verdict), `get_strings`,
`scan_secrets`, `yara_scan`, `apk_info`, `capa_scan` (capabilities + ATT&CK),
`threat_intel` (MalwareBazaar lookup), `diff_binaries`, `disassemble`.
Each returns JSON; errors come back
as `{"ok": false, "error": "..."}` — never an exception. Requires
`pip install "mcp<2"` inside Sleuth's venv (mcp 2.x removed the `fastmcp`
import path Sleuth uses). If the server won't start, fall back to the CLI
commands in the table above — same engine, same results.

## How to investigate (follow this order)

1. **Identify**: `sleuth analyze` first — it reports file type, size, verdict,
   and every signal with its exact evidence.
2. **Read the verdict honestly**:
   - `CLEAN` = no suspicious signals found. Say what was checked; do NOT
     claim "this file is 100% safe" — static analysis cannot prove safety.
   - `SUSPICIOUS` = worth a closer look. Walk the user through each signal
     and its evidence, one at a time.
   - `MALICIOUS-LOOKING` = strong indicators. Advise: do NOT run the file,
     delete or quarantine it, and consider submitting it to VirusTotal.
3. **Cite evidence, never invent**: every claim you make must point at a
   signal Sleuth reported (section name, import name, matched string). If
   Sleuth found nothing, say so plainly.
4. **Explain simply**: the user is a student. One idea at a time, everyday
   analogies before jargon.

## Example prompts the user might give you

- "Investigate this file for me: ~/downloads/setup.exe"
- "Does this APK ask for suspicious permissions? Check the strings."
- "I found this script in my email attachments — is it dangerous?"
- "Explain what this binary does, step by step, using the Sleuth report."

## Hard rules

- NEVER suggest running an unknown binary to "see what happens".
- NEVER print a full secret — Sleuth redacts previews; keep it that way.
- Scores and verdicts are heuristics, not proof. Say "looks like" / "suggests",
  never "this IS malware" — with ONE exception: a MalwareBazaar "known
  malware" hit means the hash is a confirmed published sample, and you may
  say so (cite the family name).
- Only the threat-intel lookup touches the network (it sends just the SHA256
  hash, never the file). Everything else is fully offline. If the user wants
  a VirusTotal check, they do the upload themselves in their browser.
- Refuse files over 200 MB (Sleuth enforces this itself).
