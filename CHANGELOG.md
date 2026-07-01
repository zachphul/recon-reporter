# Changelog

All notable changes to Recon Reporter.

## [0.7.0] — 2026-06-30 — bug bounty support
### Added
- **Bug bounty scope parser** (`auth/bugbounty.py`) — loads program scope from YAML/JSON with
  wildcard domains (*.example.com), CIDR ranges, and exclusion lists. Respects program rules
  and rejects out-of-scope targets.
- **Bug bounty report format** (`report/bugbounty.py`) — exports findings as structured JSON
  with CVSS ranges, platform-specific severity ratings (Bugcrowd, HackerOne, Intigriti),
  reproduction steps, and impact analysis. Ready for direct submission.
- **`--bug-bounty` CLI flag** — loads scope from a bug bounty program definition file and
  generates a `bugbounty.json` report alongside standard outputs.
- **Remediation templates** (`ai/remediation.py`) — actionable, copy-pasteable commands for
  20+ common findings (SSH, Telnet, FTP, databases, TLS, services). Used as fallback when AI
  is disabled and as supplement when AI is enabled. +10 tests.

## [0.6.0] — 2026-06-30 — SSH analysis
### Added
- **SSH key analysis** — detects weak key exchange algorithms (DH Group 1, DH Group 14 with SHA-1),
  weak host key algorithms (DSA, RSA with SHA-1), weak ciphers (arcfour, 3des, des, blowfish),
  weak MACs (hmac-md5, hmac-sha1-96), and short RSA host keys (< 2048-bit). Each finding includes
  specific remediation steps (sshd_config directives, ssh-keygen commands). +3 tests.

## [0.5.1] — 2026-06-30 — bug fixes
### Fixed
- **WhatWeb target matching** — results now match by hostname instead of merging into ALL hosts; prevents incorrect tech attributions on multi-host scans.
- **XML bomb vulnerability** — switched from `xml.etree.ElementTree` to `defusedxml` to prevent billion-laughs attacks via `--offline`.
- **MCP server DRY violation** — `_run_scan` now calls `run_pipeline()` instead of duplicating logic; implemented missing `recon_scan` tool.
- **CSV injection protection** — cells starting with `=`, `+`, `-`, `@` are now prefixed with `'` to prevent formula injection.
- **Scope file encoding** — `read_text()` now uses explicit `encoding="utf-8"` to prevent Windows cp1252 issues.
- **JSON extraction regex** — changed greedy `{.*\}` to non-greedy `{.*?}` in `_extract_json` to prevent invalid captures.
- **Diff severity tracking** — flag comparison now includes severity level to detect when severity changes between runs.
- **Cross-platform path display** — replaced hardcoded `\` with `Path /` operator for Linux/macOS compatibility.
- **Import placement** — moved `import re` from function body to module level in rules.py; added type annotation to `_outdated_flag` parameter.

## [0.5.0] — 2026-06-28 — stretch features
### Added
- **`monitor` command** — scan a target and diff it against its most recent prior run; writes
  `diff.md`; `--fail-on-new` exits 1 when findings appear (for CI/alerting).
- **`dashboard` command** — aggregate every run under `runs/` into a single dark HTML index.
- **Optional `--pdf`** export (weasyprint; degrades gracefully with a how-to when absent).
- **Expanded rule packs** — VNC/remote-access exposure (HIGH), legacy/risky services
  (MSRPC, rpcbind, LDAP, X11, NFS, r-services), more sensitive datastores, and a host-level
  "large attack surface" check. +2 tests.
- **CPE-based CVE matching** — known products (OpenSSH, Apache, nginx, …) query NVD by precise
  CPE (`virtualMatchString`) instead of fuzzy keyword search, cutting false positives; unknown
  products fall back to keyword. +2 tests.
- **CSV findings export** (`findings.csv`, every run) — flat, severity-ranked rows for triage
  in a spreadsheet or SIEM import. +1 test.
- **Terminal findings table** — a color-coded, severity-ranked summary prints at the end of a
  scan (rich). +1 test.
- **`_execute_scan` helper** — scan & monitor share one gate→pipeline→persist core (DRY).
- `make_run_dir` now collision-safe for back-to-back runs; `store.latest_findings()` lookup.
- CLI integration tests (Typer runner) + store/dashboard/PDF tests. Suite 25 → **43**.

## [0.4.0] — 2026-06-28 — long-term hardening
### Added
- **Extracted `pipeline.run_pipeline()`** — the recon pipeline is now a pure, unit-testable
  function; the CLI is a thin shell over it (also reusable by the MCP server). +2 pipeline tests.
- **Logging layer** (`logconf.py`) + `--verbose`; collectors/CVE/AI log failures with reasons
  instead of swallowing them silently.
- **ruff + mypy** configured and **clean**; `py.typed` marker (typed package).
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
