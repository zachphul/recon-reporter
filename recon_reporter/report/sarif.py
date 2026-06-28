"""Export findings as SARIF 2.1.0 — the standard format consumed by GitHub code
scanning, Azure DevOps, and most security dashboards. Lets a Recon Reporter run feed
straight into a CI security gate."""
from __future__ import annotations

import hashlib
import json

from .. import __version__
from ..ai.base import Analysis
from ..model import ScanRun, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_id(title: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")[:60]


def to_sarif(scan: ScanRun, analysis: Analysis | None) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    def add(title: str, severity: Severity, location: str, text: str):
        rid = _rule_id(title)
        loc = location or scan.target
        rules.setdefault(rid, {
            "id": rid,
            "name": title,
            "shortDescription": {"text": title},
            "fullDescription": {"text": title},
            "help": {"text": f"{title}. Review the affected service and remediate."},
            "defaultConfiguration": {"level": _LEVEL[severity]},
        })
        # Stable fingerprint so the same finding dedups across runs in code-scanning UIs.
        fp = hashlib.sha256(f"{rid}|{loc}".encode()).hexdigest()[:16]
        results.append({
            "ruleId": rid,
            "level": _LEVEL[severity],
            "message": {"text": text},
            "properties": {"severity": severity.value},
            "partialFingerprints": {"reconReporter/v1": fp},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": loc}}
            }],
        })

    if analysis:
        for f in analysis.findings:
            add(f.title, f.severity, f.affected, f"{f.why_it_matters} Remediation: {f.remediation}")
    else:
        for fl in scan.flags:
            loc = f"{fl.host}:{fl.port}" if fl.port else fl.host
            add(fl.title, fl.severity, loc, fl.detail)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "Recon Reporter",
                "version": __version__,
                "informationUri": "https://github.com/zachphul/recon-reporter",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def dumps(scan: ScanRun, analysis: Analysis | None) -> str:
    return json.dumps(to_sarif(scan, analysis), indent=2)
