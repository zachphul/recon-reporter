"""Risk scoring engine — quantifies findings into a single 0-100 risk score.

Factors:
  - Severity distribution (critical findings dominate the score)
  - Attack surface size (more open services = more risk)
  - CVE exposure (known exploitable vulns increase risk)
  - Service diversity (databases, remote access, legacy services)
  - Configuration weaknesses (weak crypto, cleartext protocols)

The score is designed to be comparable across scans and over time (for drift monitoring).
"""
from __future__ import annotations

from ..model import ScanRun, Severity

# Severity weights (how much each finding contributes to the risk score)
_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}

# Bonus points for high-risk service categories
_RISKY_SERVICES = {
    "telnet": 10,
    "ftp": 5,
    "vnc": 12,
    "rdp": 8,
    "mysql": 6,
    "postgresql": 6,
    "mongodb": 8,
    "redis": 10,
    "elasticsearch": 8,
    "smb": 7,
    "nfs": 5,
    "x11": 6,
    "ldap": 4,
}


def calculate_risk(scan: ScanRun) -> tuple[int, dict[str, int]]:
    """Calculate a risk score (0-100) and breakdown for a scan.

    Returns (score, breakdown) where breakdown shows contribution by category.
    """
    breakdown: dict[str, int] = {}

    # 1) Severity-based scoring from rule flags
    severity_score = 0
    for flag in scan.flags:
        severity_score += _SEVERITY_WEIGHTS.get(flag.severity, 0)
    breakdown["findings"] = min(severity_score, 50)  # cap at 50

    # 2) Attack surface scoring
    total_services = sum(len(h.services) for h in scan.hosts)
    total_hosts = len(scan.hosts)
    surface_score = min(total_hosts * 2 + total_services, 20)  # cap at 20
    breakdown["attack_surface"] = surface_score

    # 3) CVE exposure scoring
    cve_score = 0
    for h in scan.hosts:
        for s in h.services:
            for c in s.cves:
                if c.kev:
                    cve_score += 10  # known exploited vuln
                elif c.epss and c.epss > 0.5:
                    cve_score += 5   # likely to be exploited
                elif c.cvss and c.cvss >= 9.0:
                    cve_score += 8   # critical CVSS
                elif c.cvss and c.cvss >= 7.0:
                    cve_score += 4   # high CVSS
    breakdown["cve_exposure"] = min(cve_score, 20)  # cap at 20

    # 4) Service risk scoring
    service_score = 0
    for h in scan.hosts:
        for s in h.services:
            svc_name = (s.service or "").lower()
            for pattern, points in _RISKY_SERVICES.items():
                if pattern in svc_name:
                    service_score += points
                    break
    breakdown["service_risk"] = min(service_score, 20)  # cap at 20

    # 5) Configuration weakness scoring (from script output)
    config_score = 0
    weak_indicators = [
        "anonymous", "cleartext", "weak", "deprecated",
        "export", "null", "rc4", "des", "md5",
    ]
    for h in scan.hosts:
        for s in h.services:
            blob = " ".join(s.scripts.values()).lower()
            for indicator in weak_indicators:
                if indicator in blob:
                    config_score += 2
    breakdown["config_weakness"] = min(config_score, 10)  # cap at 10

    # Calculate final score (sum of all categories, capped at 100)
    total = sum(breakdown.values())
    score = min(total, 100)

    return score, breakdown


def risk_label(score: int) -> str:
    """Human-readable risk label for a score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    return "MINIMAL"
