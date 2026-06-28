# Changelog

All notable changes to Recon Reporter.

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
