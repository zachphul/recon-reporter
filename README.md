# Recon Reporter

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
recon-reporter scan scanme.nmap.org --scope scope.yml --authorized

# Rule-based report only (no LLM)
recon-reporter scan 127.0.0.1 --scope scope.yml --authorized --no-ai

# Offline: feed an existing nmap XML, no scanning, no scope needed (for testing)
recon-reporter scan demo --offline tests/fixtures/sample_nmap.xml --no-scope-check
```

Output lands in `runs/<target>-<timestamp>/`: `report.md`, `findings.json`, and `raw/`.

## AI provider (auto)

- If `ANTHROPIC_API_KEY` is set → uses **Claude** (`claude-opus-4-8`) with structured outputs.
- Otherwise → uses a **local** OpenAI-compatible endpoint (LM Studio / Ollama) at
  `http://localhost:1234/v1`. Free and offline.

Override with env: `RR_PROVIDER=claude|local`, `RR_CLAUDE_MODEL`, `RR_LOCAL_URL`, `RR_LOCAL_MODEL`.

Every AI finding is **grounded**: if its affected host:port isn't present in the actual scan,
it's flagged in the report rather than trusted — the main guard against hallucinated vulns.

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
- [ ] Phase 2 — NVD CVE enrichment, HTML/PDF report, whatweb + TLS collectors
- [ ] Phase 3 — scan-to-scan diff, MCP server wrapper, web dashboard

## Tests

```bash
pip install -e ".[dev]" && pytest -q
```

## License

MIT.
