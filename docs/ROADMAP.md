# Roadmap

## ✅ Phase 0/1 — core pipeline (shipped)
- Scope/authorization gate
- Nmap collector + XML parser → canonical model
- Deterministic rule engine
- Provider-abstracted AI analyst (Claude / local) with evidence grounding
- Markdown report, run storage, CLI, tests

## ✅ Phase 2 — depth (shipped)
- NVD CVE enrichment (cached, rate-limited, offline-safe) → `--cve`
- Self-contained dark **HTML report** (always emitted alongside Markdown)
- WhatWeb + sslscan collectors → `--web`
- **Scan diff** command (asset drift over time)
- **MCP server** wrapper (exposes recon as an agent tool — ties the MCP cert)

## ⏳ Phase 3 — ideas
- [ ] PDF export (weasyprint) for client-ready deliverables
- [ ] HTTP collector (`httpx`) — headers, security-header grading
- [ ] More rule packs (CIS-style checks, exposed-secret heuristics)
- [ ] Severity calibration from CVSS + exposure (move beyond keyword CVE match to CPE)
- [ ] Scheduled monitoring mode (cron → scan → diff → alert on new findings)
- [ ] Web dashboard (read `findings.json` history, trend charts)
- [ ] HTML template themes (match the portfolio site)

## Known limitations (be honest in the report)
- CVE matching is **version/keyword-based**, not strict CPE — findings are *potential* and
  flagged as needing verification.
- The AI layer summarizes; it does not exploit or confirm. Always human-verify before acting.
- WhatWeb/sslscan parsing is summary-level, not exhaustive.
