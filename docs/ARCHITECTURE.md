# Architecture

Recon Reporter is a pipeline: each stage has one job and hands a typed object to the next.
The guiding rule — **the AI and report layers never touch raw tool output; they only read
the canonical model.** That keeps the system deterministic, testable, and hard to fool.

```
 target + scope
      │
      ▼
 ┌───────────────┐   refuses anything not in scope.yml + requires --authorized
 │ Authorization │   (auth/scope.py)
 └──────┬────────┘
        ▼
 ┌───────────────┐   nmap (collectors/nmap.py) → raw XML
 │  Collectors   │   + optional whatweb, sslscan (collectors/*.py)
 └──────┬────────┘
        ▼
 ┌───────────────┐   raw → typed model (parsers/nmap_xml.py)
 │   Parsers     │   Host ▸ Service ▸ scripts
 └──────┬────────┘
        ▼
 ┌───────────────┐   deterministic: NVD CVE match (enrich/cve.py)
 │  Enrichment   │   + heuristic rules (enrich/rules.py) → RuleFlags
 └──────┬────────┘
        ▼
 ┌───────────────┐   structured findings → LLM → severity, impact, remediation
 │  AI Analyst   │   Claude OR local LM Studio (ai/*.py)
 │               │   every finding GROUNDED to real scan endpoints
 └──────┬────────┘
        ▼
 ┌───────────────┐   Markdown + self-contained dark HTML (report/*.py)
 │   Reporting   │
 └──────┬────────┘
        ▼
 runs/<target>-<timestamp>/  raw/ · findings.json · report.md · report.html
```

## The canonical model (`model.py`)

```
ScanRun
 ├─ target, started_at, finished_at, tool_versions
 ├─ hosts: [Host]
 │    ├─ address, hostname, os_guess
 │    └─ services: [Service]
 │         ├─ port, protocol, service, product, version
 │         ├─ scripts: {name: output}      ← nmap scripts, whatweb, sslscan all land here
 │         └─ cves: [CveRef]               ← from NVD enrichment
 └─ flags: [RuleFlag]                       ← deterministic findings
```

Why one model: every collector converges here, so adding a tool never touches the AI or
report code. The rules engine and the AI both read `scripts` text, so a new collector that
writes a useful string into `scripts` is automatically considered downstream.

## Why structured findings → LLM (not raw dumps)

1. **Token efficiency** — a 2,000-line nmap dump becomes a few hundred tokens of structured facts.
2. **Determinism** — same scan → same prompt → cache-friendly, reproducible.
3. **Anti-hallucination** — the model can't misread tool quirks it never sees; and every
   finding it returns is checked against `ScanRun.all_endpoints()` (`ai/base.py:ground`).
   Ungrounded findings are flagged in the report, not silently trusted.

## Extending it

| Add a… | Do this |
|--------|---------|
| Collector | Subclass `collectors.base.Collector`; write a `merge_into_hosts()` or a parser into `model.py` types |
| Enrichment | Add a function over `list[Host]` returning `RuleFlag`s or mutating services |
| Report format | Add `report/<fmt>.py` reading `ScanRun` + `Analysis` |
| AI provider | Add `ai/<provider>.py` with an `analyze(scan) -> Analysis` method; wire into `ai/analyst.py` |

## Trust boundaries

- **Authorization** is enforced before any packet leaves the host (`auth/scope.py`).
- **Secrets** (API keys) come from env only; never written to run output.
- **Run output may contain scan data** → `runs/` is git-ignored by default.
