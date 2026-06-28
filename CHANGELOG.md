# Changelog

All notable changes to Recon Reporter.

## [0.5.0] — 2026-06-28 — stretch features
### Added
- **`monitor` command** — scan a target and diff it against its most recent prior run; writes
  `diff.md`; `--fail-on-new` exits 1 when findings appear (for CI/alerting).
- **`dashboard` command** — aggregate every run under `runs/` into a single dark HTML index.
- **Optional `--pdf`** export (weasyprint; degrades gracefully with a how-to when absent).
- **`_execute_scan` helper** — scan & monitor share one gate→pipeline→persist core (DRY).
- `make_run_dir` now collision-safe for back-to-back runs; `store.latest_findings()` lookup.
- CLI integration tests (Typer runner) + store/dashboard/PDF tests. Suite 25 → **34**.

## [0.4.0] — 2026-06-28 — long-term hardening
### Added
- **Extracted `pipeline.run_pipeline()`** — the recon pipeline is now a pure, unit-testable
  function; the CLI is a thin shell over it (also reusable by the MCP server). +2 pipeline tests.
- **Logging layer** (`logconf.py`) + `--verbose`; collectors/CVE/AI log failures with reasons
  instead of swallowing them silently.
- **ruff + mypy** configured and **clean** across 31 source files; `py.typed` marker (typed package).
- CI runs **ruff + mypy + pytest** (was pytest only). `.gitattributes` (eol=lf).
- Local AI analyst: JSON **repair + retry**; CVE parse/cache tests; SARIF dedup fingerprints +
  rule help; empty-scan report tests; robust version parsing (epochs/suffixes).
- Test suite grew 13 → **25**, all offline.
### Changed
- `--http` TLS verification is **on by default**; opt out with `--insecure`.
- `docs/QUALITY-PLAN.md` — the long-term hardening plan and quality bar.

## [0.3.1] — 2026-06-28
### Added
- **Outdated-software detection** in the rule engine — version-compares disclosed products
  (OpenSSH, Apache, nginx, vsftpd, …) against a recent baseline and flags potentially old builds.
- Docs: `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/EXAMPLES.md`; GitHub Actions CI workflow.
- 13 tests total.

## [0.3.0] — 2026-06-28
### Added
- **HTTP security-header collector** (`collectors/http_headers.py`) — pure-Python (httpx),
  grades HSTS/CSP/X-Frame-Options/etc. and flags Server-header disclosure. Runs anywhere. `--http`.
- **SARIF 2.1.0 export** (`report/sarif.py`) — every run now also writes `report.sarif.json`
  for GitHub code-scanning / CI security gates.
- Phase 3 tests (header grading + SARIF) — 11 tests total.

## [0.2.0] — 2026-06-28
### Added
- **NVD CVE enrichment** (`enrich/cve.py`) with on-disk caching and graceful offline degradation — `--cve`.
- **HTML report** (`report/html.py`) — self-contained dark theme, emitted alongside Markdown.
- **WhatWeb** and **sslscan** collectors (`collectors/whatweb.py`, `collectors/tls.py`) — `--web`.
- **`diff` command** — compares two `findings.json` runs (opened/closed ports, changed services, new flags).
- **MCP server** wrapper (`mcp_server.py`) — exposes recon as an MCP tool with the scope gate applied.
- Docs: `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `docs/ROADMAP.md`; tests for Phase 2 (8 total).

### Changed
- Rule evaluation now runs **after** all collectors merge, so WhatWeb/sslscan findings feed the rules.
- UTF-8 stdout safeguard for Windows consoles.

## [0.1.0] — 2026-06-28
### Added
- Scope/authorization gate, Nmap collector + XML parser, canonical Pydantic model.
- Deterministic rule engine; provider-abstracted AI analyst (Claude/local) with grounding.
- Markdown report, run storage, CLI, 4 tests, README with authorized-use policy.
