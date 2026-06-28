# Usage

## Install

```bash
python -m venv .venv && . .venv/bin/activate     # (Windows: .venv\Scripts\activate)
pip install -e ".[dev]"
cp scope.example.yml scope.yml                   # then edit to your authorized targets
```

Nmap must be on `PATH`. WhatWeb and sslscan are optional (used by `--web`); Kali ships all three.

## Authorization (read first)

The tool **refuses** any target not listed in your scope file, and requires `--authorized`:

```yaml
# scope.yml
authorized_targets:
  - scanme.nmap.org
  - 127.0.0.1
  - 192.168.56.0/24
```

Hostnames are matched literally; IPs/CIDRs are matched after DNS resolution. There is no
flag to disable this for a live scan — by design.

## Commands

### `scan`

```bash
recon-reporter scan <target> [options]
```

| Option | Purpose |
|--------|---------|
| `--scope PATH` | Scope file (default `scope.yml`) |
| `--authorized` | Assert you may test this target (required for live scans) |
| `--profile` | `default` (top 1000, -sV -sC) · `quick` (-F) · `full` (-p-) |
| `--cve` | Enrich services with NVD CVE matches (network; cached) |
| `--web` | Also run WhatWeb + sslscan |
| `--no-ai` | Rule-based report only (no LLM) |
| `--offline PATH` | Use an existing nmap XML instead of scanning |
| `--no-scope-check` | Skip the scope gate — **only valid with `--offline`** |
| `--out PATH` | Output root (default `runs/`) |

Examples:

```bash
# Full assessment with CVEs, web/TLS recon, and an AI report
recon-reporter scan scanme.nmap.org --scope scope.yml --authorized --cve --web

# Fast, rule-only, no network beyond the scan
recon-reporter scan 127.0.0.1 --scope scope.yml --authorized --no-ai

# Offline replay of a saved scan (for dev / CI)
recon-reporter scan demo --offline tests/fixtures/sample_nmap.xml --no-scope-check --no-ai
```

Output: `runs/<target>-<timestamp>/` → `report.md`, `report.html`, `findings.json`, `raw/`.

### `diff`

```bash
recon-reporter diff <old findings.json> <new findings.json> [--out diff.md]
```

Reports newly open / closed ports, changed services, and new rule flags between two runs —
asset drift monitoring.

## AI provider

Auto-selected:

- `ANTHROPIC_API_KEY` set → **Claude** (`claude-opus-4-8`, structured outputs).
- Otherwise → **local** OpenAI-compatible endpoint (LM Studio / Ollama) at `http://localhost:1234/v1`.

Env overrides: `RR_PROVIDER` (`claude`|`local`), `RR_CLAUDE_MODEL`, `RR_LOCAL_URL`,
`RR_LOCAL_MODEL`, `NVD_API_KEY` (raises NVD rate limits).

## MCP server (optional)

```bash
pip install mcp
python -m recon_reporter.mcp_server
```

Exposes `recon_rules(target, scope_file, authorized)` as an MCP tool an agent can call —
with the same scope gate applied.

## Tests

```bash
pytest -q          # 8 tests, fully offline
```
