# Contributing

## Setup
```bash
pip install -e ".[dev]"
pytest -q
```

## Adding a collector
1. Subclass `recon_reporter.collectors.base.Collector` (`name`, `binary`, `run()`).
2. Either parse into `model.py` types, or write a `merge_into_hosts(raw, hosts)` that augments
   existing services' `scripts`.
3. Wire it into `cli.py` (behind a flag) and add a parser/merge test using a fixture — **no
   live network in tests**.

## Principles
- The AI and report layers read **only** the canonical model — never raw tool output.
- Every AI finding must be grounded against real scan endpoints.
- Authorization is non-negotiable: nothing scans a target outside `scope.yml`.
- Be honest about limitations in the report (e.g. version-based CVE matching is *potential*).

## Tests
All tests run offline against fixtures. Add one per new parser/merge/rule.
