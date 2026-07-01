"""Flat CSV export of findings — for triage in a spreadsheet or import into a SIEM/ticketing
system. One row per finding, severity-ranked, machine-friendly."""
from __future__ import annotations

import csv
import io

from ..ai.base import Analysis
from ..model import ScanRun

# Prefix characters that could be interpreted as formulas in spreadsheet software.
_CSV_INJECTION_CHARS = ("=", "+", "-", "@")


def _sanitize(val: str) -> str:
    """Prefix cells that start with formula-significant characters to prevent CSV injection."""
    if val and val[0] in _CSV_INJECTION_CHARS:
        return "'" + val
    return val


def to_csv(scan: ScanRun, analysis: Analysis | None) -> str:
    out = io.StringIO()
    # lineterminator="\n" avoids the \r\n that becomes \r\r\n (blank lines) once the text
    # is written to a file on Windows.
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["severity", "title", "affected", "detail", "source"])

    if analysis:
        rows = [
            (f.severity, f.title, f.affected, f.why_it_matters,
             "ai" if f.grounded else "ai/ungrounded")
            for f in analysis.findings
        ]
    else:
        rows = [
            (fl.severity, fl.title, f"{fl.host}:{fl.port}" if fl.port else fl.host,
             fl.detail, "rule")
            for fl in scan.flags
        ]

    for sev, title, affected, detail, source in sorted(rows, key=lambda r: r[0].rank, reverse=True):
        w.writerow([sev.value, _sanitize(title), _sanitize(affected), _sanitize(detail), source])

    return out.getvalue()
