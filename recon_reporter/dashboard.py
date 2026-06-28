"""Aggregate all runs under runs/ into a single dark HTML dashboard — an at-a-glance
history of every assessment with severity counts and links to each report."""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from .logconf import get_logger
from .model import ScanRun, Severity
from .store import iter_run_dirs

log = get_logger(__name__)

_COLOR = {
    Severity.CRITICAL: "#e0533d", Severity.HIGH: "#e0894d", Severity.MEDIUM: "#e0c24d",
    Severity.LOW: "#6ec97a", Severity.INFO: "#7d8694",
}
_CSS = """
body{margin:0;background:#0b0c0f;color:#e7e9ee;font-family:'Segoe UI',system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:40px 24px}
h1{font-size:28px;margin:0 0 4px}.sub{color:#9aa1ad;margin-bottom:24px}
table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;border-bottom:1px solid #262a33;text-align:left;font-size:14px}
th{color:#9aa1ad}.mono{font-family:Consolas,monospace}a{color:#6ea8fe;text-decoration:none}a:hover{text-decoration:underline}
.sev{display:inline-block;min-width:22px;text-align:center;border-radius:6px;padding:1px 6px;font-weight:700;font-size:12px;color:#0b0c0f}
.empty{color:#9aa1ad;padding:30px 0}
"""


def _counts(run: ScanRun) -> dict[Severity, int]:
    c = dict.fromkeys(Severity, 0)
    for f in run.flags:
        c[f.severity] += 1
    return c


def build_dashboard(runs_root: str | Path = "runs") -> str:
    rows = []
    for d in iter_run_dirs(runs_root):
        try:
            run = ScanRun.model_validate_json((d / "findings.json").read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            log.warning("skipping unreadable run %s: %s", d.name, e)
            continue
        rows.append((d, run, _counts(run)))
    rows.reverse()  # newest first

    p = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>Recon Reporter — Dashboard</title><style>{_CSS}</style></head><body><div class='wrap'>"]
    p.append("<h1>Recon Reporter — Dashboard</h1>")
    p.append(f"<div class='sub'>{len(rows)} assessment(s) · generated "
             f"{html.escape(datetime.now().isoformat(timespec='seconds'))}</div>")

    if not rows:
        p.append("<div class='empty'>No runs found. Run a scan first.</div>")
    else:
        p.append("<table><tr><th>Target</th><th>When</th><th>Hosts</th>"
                 "<th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th><th>Report</th></tr>")
        for d, run, c in rows:
            when = (run.finished_at or run.started_at).isoformat(timespec="minutes")
            cells = "".join(
                f"<td><span class='sev' style='background:{_COLOR[s]}'>{c[s]}</span></td>"
                if c[s] else "<td>·</td>" for s in Severity
            )
            link = f"<a href='{html.escape(d.name)}/report.html'>open</a>"
            p.append(f"<tr><td class='mono'>{html.escape(run.target)}</td><td>{html.escape(when)}</td>"
                     f"<td>{len(run.hosts)}</td>{cells}<td>{link}</td></tr>")
        p.append("</table>")

    p.append("</div></body></html>")
    return "".join(p)
