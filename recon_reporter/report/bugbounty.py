"""Bug bounty report export — generates a structured JSON report suitable for
submission to bug bounty platforms (Bugcrowd, HackerOne, Intigriti).

Includes severity mapping, CVSS scores, reproduction steps, and impact analysis."""
from __future__ import annotations

import json
from datetime import datetime

from ..ai.base import Analysis
from ..model import ScanRun, Severity

# Map our severity levels to CVSS v3.1 base score ranges and platform-specific ratings
SEVERITY_MAP = {
    Severity.CRITICAL: {
        "cvss_range": "9.0 - 10.0",
        "bugcrowd": "critical",
        "hackerone": "critical",
        "intigriti": "critical",
        "label": "Critical",
    },
    Severity.HIGH: {
        "cvss_range": "7.0 - 8.9",
        "bugcrowd": "high",
        "hackerone": "high",
        "intigriti": "high",
        "label": "High",
    },
    Severity.MEDIUM: {
        "cvss_range": "4.0 - 6.9",
        "bugcrowd": "medium",
        "hackerone": "medium",
        "intigriti": "medium",
        "label": "Medium",
    },
    Severity.LOW: {
        "cvss_range": "0.1 - 3.9",
        "bugcrowd": "low",
        "hackerone": "low",
        "intigriti": "low",
        "label": "Low",
    },
    Severity.INFO: {
        "cvss_range": "0.0",
        "bugcrowd": "informational",
        "hackerone": "none",
        "intigriti": "info",
        "label": "Informational",
    },
}


def _build_reproduction_steps(finding: dict) -> list[str]:
    """Generate step-by-step reproduction instructions from a finding."""
    steps = []
    affected = finding.get("affected", "")
    evidence = finding.get("evidence", "")
    title = finding.get("title", "")

    steps.append(f"1. Run a port scan against the target: nmap -sV -sC {affected.split(':')[0]}")
    if evidence:
        steps.append(f"2. Observe the following evidence: {evidence}")
    steps.append(f"3. The finding '{title}' is present at {affected}")
    steps.append("4. Document the observed behavior and its security implications")
    return steps


def _build_impact(finding: dict) -> str:
    """Generate an impact statement based on severity and finding type."""
    severity = finding.get("severity", "info")
    title = finding.get("title", "").lower()

    impact_templates = {
        "critical": (
            "Critical severity: This vulnerability could allow complete system compromise, "
            "data exfiltration, or unauthorized access to sensitive resources. Immediate "
            "remediation is strongly recommended."
        ),
        "high": (
            "High severity: This vulnerability could allow significant unauthorized access "
            "or data exposure. Prompt remediation is recommended."
        ),
        "medium": (
            "Medium severity: This vulnerability could be chained with other issues to "
            "escalate access or could expose sensitive information under certain conditions."
        ),
        "low": (
            "Low severity: This vulnerability represents a minor security weakness that "
            "could be leveraged in combination with other findings."
        ),
        "info": (
            "Informational: This finding does not represent a direct vulnerability but "
            "provides context that could be useful for an attacker conducting reconnaissance."
        ),
    }

    base = impact_templates.get(severity, impact_templates["info"])

    # Add specific impact based on finding type
    if "telnet" in title:
        base += " Credentials transmitted in cleartext can be intercepted by network observers."
    elif "anonymous ftp" in title:
        base += " Unauthenticated users can access and potentially modify files on the server."
    elif "ssh" in title and "weak" in title:
        base += " Weak SSH configurations can be exploited to intercept sessions or gain unauthorized access."
    elif "database" in title or "mysql" in title or "postgresql" in title or "mongodb" in title:
        base += " Exposed databases can lead to data breaches and unauthorized data access."

    return base


def to_bugbounty_json(
    scan: ScanRun,
    analysis: Analysis | None,
    program_name: str = "",
    program_url: str = "",
) -> str:
    """Export findings as a structured JSON report for bug bounty submission.

    The output follows a format compatible with Bugcrowd, HackerOne, and Intigriti
    submission APIs, with additional metadata for automation.
    """
    findings = []
    if analysis:
        for f in analysis.findings:
            sev_map = SEVERITY_MAP.get(f.severity, SEVERITY_MAP[Severity.INFO])
            finding = {
                "title": f.title,
                "severity": sev_map["label"],
                "cvss_range": sev_map["cvss_range"],
                "affected": f.affected,
                "description": f.why_it_matters,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "grounded": f.grounded,
                "reproduction_steps": _build_reproduction_steps({
                    "affected": f.affected,
                    "evidence": f.evidence,
                    "title": f.title,
                }),
                "impact": _build_impact({
                    "severity": sev_map["bugcrowd"],
                    "title": f.title,
                }),
                "platform_ratings": {
                    "bugcrowd": sev_map["bugcrowd"],
                    "hackerone": sev_map["hackerone"],
                    "intigriti": sev_map["intigriti"],
                },
            }
            if f.remediation_steps:
                finding["remediation_steps"] = [
                    {"action": s.action, "command": s.command, "description": s.description}
                    for s in f.remediation_steps
                ]
            findings.append(finding)
    else:
        for fl in scan.flags:
            sev_map = SEVERITY_MAP.get(fl.severity, SEVERITY_MAP[Severity.INFO])
            loc = f"{fl.host}:{fl.port}" if fl.port else fl.host
            finding = {
                "title": fl.title,
                "severity": sev_map["label"],
                "cvss_range": sev_map["cvss_range"],
                "affected": loc,
                "description": fl.detail,
                "reproduction_steps": _build_reproduction_steps({
                    "affected": loc,
                    "evidence": fl.detail,
                    "title": fl.title,
                }),
                "impact": _build_impact({
                    "severity": sev_map["bugcrowd"],
                    "title": fl.title,
                }),
                "platform_ratings": {
                    "bugcrowd": sev_map["bugcrowd"],
                    "hackerone": sev_map["hackerone"],
                    "intigriti": sev_map["intigriti"],
                },
            }
            findings.append(finding)

    report = {
        "report_type": "reconlens",
        "report_version": "1.0",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": scan.target,
        "program": {
            "name": program_name,
            "url": program_url,
        },
        "scope": {
            "hosts_scanned": len(scan.hosts),
            "services_found": sum(len(h.services) for h in scan.hosts),
            "findings_count": len(findings),
        },
        "findings": findings,
        "metadata": {
            "tool_versions": scan.tool_versions,
            "scan_started": scan.started_at.isoformat(timespec="seconds"),
            "scan_finished": scan.finished_at.isoformat(timespec="seconds") if scan.finished_at else None,
        },
    }

    return json.dumps(report, indent=2, ensure_ascii=False)
