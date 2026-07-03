# ReconLens

**AI-assisted reconnaissance reporting.** Runs on Kali, orchestrates Nmap, normalizes the
results into one data model, applies deterministic security rules, then uses an LLM to write
a prioritized, plain-English security assessment report.

> The boring half of a pentest report, automated — you keep the judgment.

---

## ⚠️ Authorized use only

This tool performs active reconnaissance. **Only run it against systems you own or have
explicit written permission to test.** It enforces this with a scope file: it refuses any
target not listed in `scope.yml` unless you pass `--authorized`.

Sanctioned practice targets: [`scanme.nmap.org`](http://scanme.nmap.org), your own lab VMs,
[DVWA](https://github.com/digininja/DVWA), [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).

Unauthorized scanning may be illegal. You are responsible for how you use this.

---

## Install

```bash
pip install -e .          # from the repo root
cp scope.example.yml scope.yml   # then edit to list your authorized targets
```

Nmap must be on PATH (Kali ships with it).

## Use

```bash
# Full run (scan + AI report)
reconlens scan scanme.nmap.org --scope scope.yml --authorized

# Rule-based report only (no LLM)
reconlens scan 127.0.0.1 --scope scope.yml --authorized --no-ai

# Offline: feed an existing nmap XML, no scanning, no scope needed (for testing)
reconlens scan demo --offline tests/fixtures/sample_nmap.xml --no-scope-check
```

Output lands in `runs/<target>-<timestamp>/`: `report.md`, `findings.json`, and `raw/`.

## AI provider (auto)

- If `ANTHROPIC_API_KEY` is set → uses **Claude** (`claude-opus-4-8`) with structured outputs.
- Otherwise → uses a **local** OpenAI-compatible endpoint (LM Studio / Ollama) at
  `http://localhost:1234/v1`. Free and offline.

Override with env: `RR_PROVIDER=claude|local`, `RR_CLAUDE_MODEL`, `RR_LOCAL_URL`, `RR_LOCAL_MODEL`.

Every AI finding is **grounded**: if its affected host:port isn't present in the actual scan,
it's flagged in the report rather than trusted — the main guard against hallucinated vulns.

## Exploitation priority (CISA KEV + EPSS)

A service can disclose dozens of CVEs; most are noise. With `--cve`, each match is annotated
with real-world exploitation signals so the report ranks by what attackers actually use — not
raw CVSS:

- **CISA KEV** — CVEs confirmed *exploited in the wild* (and those linked to ransomware). A KEV
  hit becomes its own **CRITICAL** finding and outranks any CVSS score.
- **EPSS** — the probability a CVE is exploited within 30 days, shown as a badge and used to rank
  the long tail.

So a CVSS 9.8 vuln nobody is exploiting correctly sorts *below* a CVSS 8.1 vuln that's in KEV.
Both feeds are cached and degrade gracefully offline (no network → uses cache, never crashes).

## Architecture

```
target ─▶ scope gate ─▶ collectors (nmap) ─▶ parsers ─▶ model ─▶ rules
                                                                   ▼
                          report (md) ◀── grounding ◀── AI analyst (Claude | local)
```

Add a collector by subclassing `collectors.base.Collector`; add a parser into the same
`model.py` types. The AI and report layers never read raw tool output — only the model.

## Roadmap

- [x] Phase 0/1 — Nmap collector, rules, AI report, scope gate, tests
- [x] Phase 2 — NVD CVE enrichment, HTML report, WhatWeb + TLS collectors, scan diff, MCP server
- [x] Phase 3 — HTTP header grading, SARIF export, PDF, `monitor` (drift), `dashboard`
- [x] Phase 4 — SSH crypto analysis, bug-bounty scope/export, **exploit-aware prioritization (CISA KEV + EPSS)**
- Hardened for the long term: pure testable pipeline, logging, ruff + mypy clean, 69 tests, CI-gated (see [`docs/QUALITY-PLAN.md`](docs/QUALITY-PLAN.md))

Full plan: [`docs/ROADMAP.md`](docs/ROADMAP.md) · architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · usage: [`docs/USAGE.md`](docs/USAGE.md)

## Tests

```bash
pip install -e ".[dev]" && pytest -q
```

## License

MIT.
