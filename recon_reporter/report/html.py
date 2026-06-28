"""Render a ScanRun (+ optional AI Analysis) into a self-contained dark HTML report.
No template-engine dependency — inline CSS so the file is portable/screenshot-ready."""
from __future__ import annotations

import html
from datetime import datetime

from ..ai.base import Analysis
from ..model import ScanRun, Severity

_COLOR = {
    Severity.CRITICAL: "#e0533d",
    Severity.HIGH: "#e0894d",
    Severity.MEDIUM: "#e0c24d",
    Severity.LOW: "#6ec97a",
    Severity.INFO: "#7d8694",
}
_CSS = """
:root{--bg:#0b0c0f;--panel:#13151a;--line:#262a33;--txt:#e7e9ee;--muted:#9aa1ad;--accent:#e0894d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font-family:'Segoe UI',system-ui,sans-serif;line-height:1.55}
.wrap{max-width:900px;margin:0 auto;padding:40px 24px}
h1{font-size:30px;margin:0 0 4px}h2{font-size:20px;border-bottom:1px solid var(--line);
padding-bottom:8px;margin-top:40px}h3{margin:22px 0 6px}
.banner{background:#2a1d10;border:1px solid var(--accent);border-radius:8px;padding:12px 16px;
color:#f2c79a;font-size:14px;margin:18px 0}
.meta{color:var(--muted);font-size:14px}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#0b0c0f}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.card .k{color:var(--muted);font-size:13px}.mono{font-family:Consolas,monospace;color:var(--accent)}
.matrix td{text-align:center;font-size:18px;font-weight:700}
.warn{color:#e0c24d;font-size:13px}
footer{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:14px}
"""


def _e(s: str) -> str:
    return html.escape(str(s))


def _pill(sev: Severity) -> str:
    return f'<span class="pill" style="background:{_COLOR[sev]}">{sev.value.upper()}</span>'


def render(scan: ScanRun, analysis: Analysis | None) -> str:
    findings = analysis.findings if analysis else []
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    if not findings:
        for fl in scan.flags:
            counts[fl.severity] += 1

    p: list[str] = []
    p.append(f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Security Assessment — {_e(scan.target)}</title><style>{_CSS}</style></head><body><div class='wrap'>")
    p.append(f"<h1>Security Assessment</h1>")
    p.append(f"<div class='meta'>Target: <span class='mono'>{_e(scan.target)}</span> · "
             f"{_e(scan.started_at.isoformat(timespec='seconds'))}</div>")
    p.append("<div class='banner'>⚠ Authorized testing only — generated against a target the "
             "operator asserted they own or are permitted to assess.</div>")

    # matrix
    p.append("<h2>Severity summary</h2><table class='matrix'><tr>")
    for s in Severity:
        p.append(f"<th style='text-align:center'>{s.value.upper()}</th>")
    p.append("</tr><tr>")
    for s in Severity:
        p.append(f"<td style='color:{_COLOR[s]}'>{counts[s]}</td>")
    p.append("</tr></table>")

    if analysis:
        p.append("<h2>Executive summary</h2>")
        p.append(f"<p>{_e(analysis.executive_summary)}</p>")
        p.append("<h2>Findings</h2>")
        for i, f in enumerate(sorted(findings, key=lambda f: f.severity.rank, reverse=True), 1):
            warn = "" if f.grounded else "<div class='warn'>⚠ ungrounded — not matched to scan data; review</div>"
            p.append(f"<div class='card'><h3>{i}. {_e(f.title)} &nbsp;{_pill(f.severity)}</h3>{warn}"
                     f"<div class='k'>Affected</div><div class='mono'>{_e(f.affected)}</div>"
                     f"<div class='k'>Why it matters</div><div>{_e(f.why_it_matters)}</div>"
                     f"<div class='k'>Remediation</div><div>{_e(f.remediation)}</div>"
                     f"<div class='k'>Evidence</div><div>{_e(f.evidence)}</div></div>")
        p.append("<h2>Attack narrative</h2>")
        p.append(f"<p>{_e(analysis.attack_narrative)}</p>")
    else:
        p.append("<h2>Rule-based findings</h2>")
        for fl in sorted(scan.flags, key=lambda f: f.severity.rank, reverse=True):
            loc = f"{fl.host}:{fl.port}" if fl.port else fl.host
            p.append(f"<div class='card'>{_pill(fl.severity)} <b>{_e(fl.title)}</b> "
                     f"<span class='mono'>{_e(loc)}</span><br><span class='k'>{_e(fl.detail)}</span></div>")

    p.append("<h2>Hosts &amp; services</h2>")
    for h in scan.hosts:
        title = _e(h.address) + (f" ({_e(h.hostname)})" if h.hostname else "")
        p.append(f"<h3>{title}</h3>")
        if h.os_guess:
            p.append(f"<div class='meta'>OS guess: {_e(h.os_guess)}</div>")
        p.append("<table><tr><th>Port</th><th>Service</th><th>Product / Version</th><th>CVEs</th></tr>")
        for s in h.services:
            cves = ", ".join(c.id for c in s.cves) if s.cves else "—"
            p.append(f"<tr><td class='mono'>{s.port}/{_e(s.protocol)}</td><td>{_e(s.service or '?')}</td>"
                     f"<td>{_e(s.label or '-')}</td><td>{_e(cves)}</td></tr>")
        p.append("</table>")

    p.append(f"<footer>Generated by Recon Reporter on {_e(datetime.now().isoformat(timespec='seconds'))}.</footer>")
    p.append("</div></body></html>")
    return "".join(p)
