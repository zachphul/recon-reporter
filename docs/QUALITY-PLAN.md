# Long-Term Quality Plan

The first pass (v0.1–0.3.1) was a fast rough draft to prove the concept. This plan turns it
into something maintainable for the long term: typed, linted, observable, well-tested, and
honest about its limits. Work the sequence top-to-bottom; each item has a clear "done".

## The bar (principles)

1. **Correctness over features.** Every feature has an offline test. No feature ships red.
2. **The model is the contract.** Collectors converge into `model.py`; AI/report read only the model.
3. **Fail loud, not silent.** Errors are logged with context, never swallowed into `except: pass`.
4. **Honest output.** Grounding stays; "potential"/"verify" labels stay; no overclaiming.
5. **Authorization is non-negotiable.** The scope gate is never bypassable for a live scan.
6. **Typed + linted + CI-gated.** ruff + mypy + pytest must pass before any commit is "done".

## Critical audit of the rough draft

| Area | Issue (rough draft) | Hardening | Priority |
|------|--------------------|-----------|----------|
| Observability | Collectors `except: ... return []` swallow errors silently | Central `logging` + `--verbose`; log every skip/failure with reason | **High** |
| AI (Claude) | Single `messages.parse` call, no effort tuning, no retry | Add `effort`, robust error surfacing, optional retry; keep structured output | **High** |
| AI (local) | One JSON parse attempt; malformed model output → crash | JSON repair + one retry with a stricter instruction | **High** |
| Tooling | No ruff/mypy config, no `py.typed` | Add configs, type-clean the package, ship `py.typed` | **High** |
| HTTP headers | `verify=False` undocumented; no per-endpoint error handling | Make TLS-verify a documented option; log per-endpoint failures | Med |
| CVE | Keyword match (imprecise); no fixture test; no parse test | Add fixture-based parse test; document as "potential"; cache key hygiene | Med |
| SARIF | No dedup fingerprints; rules lack help text | Add `partialFingerprints`; rule `help`/`fullDescription` | Med |
| Rules | Version compare ignores epochs/suffixes; thin coverage | Harden `_ver_tuple`; add a couple rule packs with tests | Med |
| Reports | Untested edge cases (no hosts, no findings) | Tests for empty scans; ensure valid output | Med |
| Packaging | Missing classifiers/urls; no coverage config | Fill `pyproject` metadata; add coverage to CI | Low |
| CLI | One big `scan` function; hard to unit-test | Extract a `pipeline.run()` callable; CLI becomes a thin shell | Med |

## Hardening sequence (go slow — verify after each)

**Foundation**
- [x] F1. Add `logging` (`logconf.py`) + `--verbose`; replace silent excepts with logged warnings.
- [x] F2. Add `ruff` + `mypy` config to `pyproject`; add `py.typed`; type-clean; wire both into CI.

**Phase 2 hardening**
- [x] P2a. Extract `pipeline.run()` from the CLI so the pipeline is unit-testable; CLI calls it.
- [x] P2b. AI layer: Claude effort + error surfacing; local JSON repair+retry; stronger grounding.
- [x] P2c. CVE: fixture parse test, cache-key hygiene, clearer "potential" labeling.
- [x] P2d. Reports: empty-scan tests; HTML/MD edge cases.

**Phase 3 hardening**
- [x] P3a. HTTP headers: documented `--insecure` toggle (default verify on); per-endpoint logging.
- [x] P3b. SARIF: `partialFingerprints` for dedup; rule `help` text; schema-shape test.
- [x] P3c. Rules: robust version parsing (suffixes/epochs); +1 rule pack with tests.

**Done = ruff clean, mypy clean, pytest green, docs updated, committed.**

## Keeping it going (maintenance)

- **Versioning:** semver; update `CHANGELOG.md` every change; tag releases.
- **Each PR:** ruff + mypy + pytest green (enforced by CI); a test for every new collector/rule.
- **Dependencies:** keep the runtime set small; pin majors; `anthropic`/`mcp` stay optional at runtime.
- **Definition of done per module:** typed · has a test · errors logged not swallowed · documented.
- **Roadmap cadence:** finish a hardening item fully before starting the next; don't half-land features.
