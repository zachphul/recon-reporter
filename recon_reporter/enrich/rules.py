"""Deterministic heuristics over parsed services. These are rule-based (not AI) so
they're reproducible and explainable — the AI layer reasons on top of them, it does
not replace them."""
from __future__ import annotations

from ..model import Host, RuleFlag, Service, Severity

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
SENSITIVE_EXPOSED = {3389: "RDP", 445: "SMB", 5432: "PostgreSQL", 3306: "MySQL",
                     27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
WEAK_TLS_MARKERS = ("SSLv3", "TLSv1.0", "TLSv1.1", "SSLv2")


def _flag(host: str, sev: Severity, title: str, detail: str, port: int | None = None) -> RuleFlag:
    return RuleFlag(title=title, severity=sev, detail=detail, host=host, port=port)


def evaluate(hosts: list[Host]) -> list[RuleFlag]:
    flags: list[RuleFlag] = []
    for h in hosts:
        for s in h.services:
            flags.extend(_evaluate_service(h.address, s))
    return flags


def _evaluate_service(host: str, s: Service) -> list[RuleFlag]:
    out: list[RuleFlag] = []
    p = s.port

    if p == 23:
        out.append(_flag(host, Severity.HIGH, "Telnet exposed",
                         "Telnet transmits credentials in cleartext; replace with SSH.", p))
    if p == 21 and any("anonymous" in v.lower() for v in s.scripts.values()):
        out.append(_flag(host, Severity.HIGH, "Anonymous FTP allowed",
                         "FTP server permits anonymous login.", p))
    if p in SENSITIVE_EXPOSED:
        out.append(_flag(host, Severity.MEDIUM, f"{SENSITIVE_EXPOSED[p]} reachable",
                         f"{SENSITIVE_EXPOSED[p]} on port {p} is exposed; restrict to trusted networks.", p))
    if p in CLEARTEXT_PORTS and p not in (80,):
        out.append(_flag(host, Severity.LOW, f"Cleartext protocol ({CLEARTEXT_PORTS[p]})",
                         "Service uses an unencrypted protocol.", p))

    blob = " ".join(s.scripts.values())
    if any(m in blob for m in WEAK_TLS_MARKERS):
        out.append(_flag(host, Severity.MEDIUM, "Weak/deprecated TLS",
                         "Server negotiates a deprecated TLS/SSL version.", p))

    if s.product and s.version:
        out.append(_flag(host, Severity.INFO, f"Version disclosed: {s.label}",
                         "Exact product/version is visible; useful for CVE matching.", p))
    return out
