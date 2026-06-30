# Changelog

All notable changes to Recon Reporter.

## [0.5.0] â€” 2026-06-28 â€” stretch features
### Added
- **`monitor` command** â€” scan a target and diff it against its most recent prior run; writes
  `diff.md`; `--fail-on-new` exits 1 when findings appear (for CI/alerting).
- **`dashboard` command** â€” aggregate every run under `runs/` into a single dark HTML index.
- **Optional `--pdf`** export (weasyprint; degrades gracefully with a how-to when absent).
- **Expanded rule packs** â€” VNC/remote-access exposure (HIGH), legacy/risky services
  (MSRPC, rpcbind, LDAP, X11, NFS, r-services), more sensitive datastores, and a host-level
  "large attack surface" check. +2 tests.
- **CPE-based CVE matching** â€” known products (OpenSSH, Apache, nginx, â€¦) query NVD by precise
  CPE (`virtualMatchString`) instead of fuzzy keyword search, cutting false positives; unknown
  products fall back to keyword. +2 tests.
- **CSV findings export** (`findings.csv`, every run) â€” flat, severity-ranked rows for triage
  in a spreadsheet or SIEM import. +1 test.
- **Terminal findings table** — a color-coded, severity-ranked summary prints at the end of a scan (rich). +1 test.
- **`_execute_scan` helper** â€” scan & monitor share one gateâ†’pipelineâ†’persist core (DRY).
- `make_run_dir` now collision-safe for back-to-back runs; `store.latest_findings()` lookup.
- CLI integration tests (Typer runner) + store/dashboard/PDF tests. Suite 25 â†’ **34**.

## [0.4.0] â€” 2026-06-28 â€” long-term hardening
### Added
- **Extracted `pipeline.run_pipeline()`** â€” the recon pipeline is now a pure, unit-testable
  function; the CLI is a thin shell over it (also reusable by the MCP server). +2 pipeline tests.
- **Logging layer** (`logconf.py`) + `--verbose`; collectors/CVE/AI log failures with reasons
  instead of swallowing them silently.
- **ruff + mypy** configured and **clean** across 31 source files; `py.typed` marker (typed package).
- CI runs **ruff + mypy + pytest** (was pytest only). `.gitattributes` (eol=lf).
- Local AI analyst: JSON **repair + retry**; CVE parse/cache tests; SARIF dedup fingerprints +
  rule help; empty-scan report tests; robust version parsing (epochs/suffixes).
- Test suite grew 13 â†’ **25**, all offline.
### Changed
- `--http` TLS verification is **on by default**; opt out with `--insecure`.
- `docs/QUALITY-PLAN.md` â€” the long-term hardening plan and quality bar.

## [0.3.1] â€” 2026-06-28
### Added
- **Outdated-software detection** in the rule engine â€” version-compares disclosed products
  (OpenSSH, Apache, nginx, vsftpd, â€¦) against a recent baseline and flags potentially old builds.
- Docs: `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/EXAMPLES.md`; GitHub Actions CI workflow.
- 13 tests total.

## [0.3.0] â€” 2026-06-28
### Added
- **HTTP security-header collector** (`collectors/http_headers.py`) â€” pure-Python (httpx),
  grades HSTS/CSP/X-Frame-Options/etc. and flags Server-header disclosure. Runs anywhere. `--http`.
- **SARIF 2.1.0 export** (`report/sarif.py`) â€” every run now also writes `report.sarif.json`
  for GitHub code-scanning / CI security gates.
- Phase 3 tests (header grading + SARIF) â€” 11 tests total.

## [0.2.0] â€” 2026-06-28
### Added
- **NVD CVE enrichment** (`enrich/cve.py`) with on-disk caching and graceful offline degradation â€” `--cve`.
- **HTML report** (`report/html.py`) â€” self-contained dark theme, emitted alongside Markdown.
- **WhatWeb** and **sslscan** collectors (`collectors/whatweb.py`, `collectors/tls.py`) â€” `--web`.
- **`diff` command** â€” compares two `findings.json` runs (opened/closed ports, changed services, new flags).
- **MCP server** wrapper (`mcp_server.py`) â€” exposes recon as an MCP tool with the scope gate applied.
- Docs: `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `docs/ROADMAP.md`; tests for Phase 2 (8 total).

### Changed
- Rule evaluation now runs **after** all collectors merge, so WhatWeb/sslscan findings feed the rules.
- UTF-8 stdout safeguard for Windows consoles.

## [0.1.0] â€” 2026-06-28
### Added
- Scope/authorization gate, Nmap collector + XML parser, canonical Pydantic model.
- Deterministic rule engine; provider-abstracted AI analyst (Claude/local) with grounding.
- Markdown report, run storage, CLI, 4 tests, README with authorized-use policy.
