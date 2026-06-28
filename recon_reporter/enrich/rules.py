"""Deterministic heuristics over parsed services. These are rule-based (not AI) so
they're reproducible and explainable — the AI layer reasons on top of them, it does
not replace them."""
from __future__ import annotations

from ..model import Host, RuleFlag, Service, Severity

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
SENSITIVE_EXPOSED = {3389: "RDP", 445: "SMB", 5432: "PostgreSQL", 3306: "MySQL",
                     27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
WEAK_TLS_MARKERS = ("SSLv3", "TLSv1.0", "TLSv1.1", "SSLv2")

# product (substring, case-insensitive) -> a recent-ish baseline version tuple.
# Anything below is flagged as POTENTIALLY outdated (verify against the vendor advisory).
OUTDATED_BASELINE = {
    "openssh": (9, 0),
    "apache httpd": (2, 4, 60),
    "nginx": (1, 24),
    "vsftpd": (3, 0),
    "proftpd": (1, 3, 8),
    "exim": (4, 96),
    "mysql": (8, 0),
}


def _flag(host: str, sev: Severity, title: str, detail: str, port: int | None = None) -> RuleFlag:
    return RuleFlag(title=title, severity=sev, detail=detail, host=host, port=port)


def _ver_tuple(s: str) -> tuple[int, ...]:
    """Extract a leading numeric version. Handles suffixes ('6.6.1p1' -> (6,6,1)) and
    Debian-style epochs ('1:2.4.7' -> (2,4,7))."""
    import re

    s = (s or "").strip()
    if ":" in s:  # strip an epoch prefix like "1:2.4.7"
        s = s.split(":", 1)[1]
    m = re.match(r"(\d+(?:\.\d+)*)", s)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _outdated_flag(host: str, s) -> RuleFlag | None:
    if not (s.product and s.version):
        return None
    name = s.product.lower()
    baseline = next((v for k, v in OUTDATED_BASELINE.items() if k in name), None)
    if not baseline:
        return None
    ver = _ver_tuple(s.version)
    if not ver:
        return None
    n = min(len(ver), len(baseline))
    if ver[:n] < baseline[:n]:
        want = ".".join(str(x) for x in baseline)
        return _flag(host, Severity.MEDIUM, f"Potentially outdated {s.product} {s.version}",
                     f"Detected {s.product} {s.version}; a recent baseline is ~{want}. "
                     f"Verify against vendor advisories for known CVEs.", s.port)
    return None


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

    outdated = _outdated_flag(host, s)
    if outdated:
        out.append(outdated)
    return out
