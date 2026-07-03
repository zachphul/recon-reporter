"""Deterministic heuristics over parsed services. These are rule-based (not AI) so
they're reproducible and explainable — the AI layer reasons on top of them, it does
not replace them."""
from __future__ import annotations

import re

from ..model import Host, RuleFlag, Service, Severity

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
SENSITIVE_EXPOSED = {3389: "RDP", 445: "SMB", 5432: "PostgreSQL", 3306: "MySQL",
                     27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
                     5984: "CouchDB", 11211: "Memcached", 9000: "PHP-FPM"}
# Interactive remote-control services reachable from the network = high risk.
REMOTE_ACCESS = {5900: "VNC", 5901: "VNC", 5902: "VNC"}
# Legacy / information-leaking services worth flagging.
LEGACY_RISKY = {135: "MSRPC", 111: "rpcbind", 389: "LDAP (cleartext)",
                6000: "X11", 2049: "NFS", 512: "rexec", 513: "rlogin", 514: "rsh"}
WEAK_TLS_MARKERS = ("SSLv3", "TLSv1.0", "TLSv1.1", "SSLv2")
# Above this many open services on one host, surface area is itself a finding.
LARGE_SURFACE_THRESHOLD = 15
# EPSS probability at/above which a (non-KEV) CVE is worth surfacing as its own finding.
EPSS_HIGH_THRESHOLD = 0.5

# --- SSH weak algorithm detection ---
WEAK_KEX = {
    "diffie-hellman-group1-sha1": ("Diffie-Hellman Group 1 (1024-bit)", Severity.HIGH),
    "diffie-hellman-group14-sha1": ("Diffie-Hellman Group 14 with SHA-1", Severity.MEDIUM),
    "diffie-hellman-group-exchange-sha1": ("DH Group Exchange with SHA-1", Severity.MEDIUM),
}
WEAK_HOST_KEY = {
    "ssh-dss": ("DSA host key", Severity.HIGH),
    "ssh-rsa": ("RSA with SHA-1 signatures", Severity.MEDIUM),
}
WEAK_CIPHERS = (
    "arcfour", "arcfour128", "arcfour256",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "des-cbc", "rijndael-cbc@lysator.liu.se",
)
WEAK_MACS = ("hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com")
SSH_MIN_RSA_BITS = 2048

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
    s = (s or "").strip()
    if ":" in s:  # strip an epoch prefix like "1:2.4.7"
        s = s.split(":", 1)[1]
    m = re.match(r"(\d+(?:\.\d+)*)", s)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _outdated_flag(host: str, s: Service) -> RuleFlag | None:
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
        # host-level: a large open surface area is a finding in itself
        n_open = sum(1 for s in h.services if s.state == "open")
        if n_open >= LARGE_SURFACE_THRESHOLD:
            flags.append(_flag(h.address, Severity.MEDIUM, "Large attack surface",
                               f"{n_open} services are open on this host; reduce exposure to "
                               f"what is strictly required."))
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
    if p in REMOTE_ACCESS:
        out.append(_flag(host, Severity.HIGH, f"{REMOTE_ACCESS[p]} remote access exposed",
                         f"{REMOTE_ACCESS[p]} remote-control service on port {p} is reachable; "
                         f"restrict to VPN/trusted networks and require strong auth.", p))
    if p in LEGACY_RISKY:
        out.append(_flag(host, Severity.MEDIUM, f"Legacy/risky service: {LEGACY_RISKY[p]}",
                         f"{LEGACY_RISKY[p]} on port {p} is often misconfigured or information-leaking.", p))
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

    if s.service == "ssh" or (s.product and "openssh" in s.product.lower()):
        out.extend(_check_ssh(host, s))

    out.extend(_check_exploit_intel(host, s))

    outdated = _outdated_flag(host, s)
    if outdated:
        out.append(outdated)
    return out


def _check_exploit_intel(host: str, s: Service) -> list[RuleFlag]:
    """Promote actively-exploited (CISA KEV) and high-EPSS CVEs to their own findings so they
    lead the report instead of being buried in a per-service CVE list. Emits nothing unless
    CVE + exploit enrichment ran (i.e. the scan used --cve)."""
    out: list[RuleFlag] = []
    # Every KEV CVE is critical — it is confirmed exploited in the wild.
    for c in s.cves:
        if not c.kev:
            continue
        detail = (f"{c.id} is in CISA's Known Exploited Vulnerabilities catalog — confirmed "
                  f"exploited in the wild. Patch or mitigate immediately per CISA guidance.")
        if c.ransomware:
            detail += " Linked to known ransomware campaigns."
        if c.epss is not None:
            detail += f" EPSS {c.epss:.0%}."
        out.append(_flag(host, Severity.CRITICAL, f"Actively exploited: {c.id}", detail, s.port))
    # The single highest-scoring non-KEV CVE, if it clears the EPSS bar (one per service so a
    # noisy CVE list does not flood the findings).
    high = [c for c in s.cves if not c.kev and (c.epss or 0) >= EPSS_HIGH_THRESHOLD]
    if high:
        top = max(high, key=lambda c: c.epss or 0)
        extra = f", CVSS {top.cvss}" if top.cvss else ""
        out.append(_flag(
            host, Severity.HIGH, f"High exploitation likelihood: {top.id}",
            f"{top.id} has an EPSS score of {top.epss:.0%} (probability of exploitation within "
            f"30 days{extra}). Prioritize remediation.", s.port))
    return out


def _check_ssh(host: str, s: Service) -> list[RuleFlag]:
    """Analyze SSH service scripts for weak algorithms, key exchange, and key sizes."""
    flags: list[RuleFlag] = []

    # Check ssh-hostkey for short keys
    hostkey_out = s.scripts.get("ssh-hostkey", "")
    for line in hostkey_out.splitlines():
        line = line.strip()
        m = re.match(r"(\d+)\s+\S+\s+\((\w+)\)", line)
        if m:
            bits, key_type = int(m.group(1)), m.group(2)
            if key_type == "RSA" and bits < SSH_MIN_RSA_BITS:
                flags.append(_flag(
                    host, Severity.MEDIUM,
                    f"Weak SSH RSA key ({bits}-bit)",
                    f"RSA host key is only {bits} bits; recommended minimum is {SSH_MIN_RSA_BITS}. "
                    f"Regenerate with: ssh-keygen -t rsa -b {SSH_MIN_RSA_BITS * 2}",
                    s.port))

    # Check ssh2-enum-algorithms for weak algorithms
    enum_out = s.scripts.get("ssh2-enum-algorithms", "")
    if enum_out:
        lower = enum_out.lower()

        for algo, (desc, sev) in WEAK_KEX.items():
            if algo in lower:
                flags.append(_flag(
                    host, sev, f"Weak SSH key exchange: {desc}",
                    f"Server supports {algo} which is considered weak. "
                    f"Remove it from the server's KexAlgorithms config.",
                    s.port))

        for algo, (desc, sev) in WEAK_HOST_KEY.items():
            if algo in lower:
                flags.append(_flag(
                    host, sev, f"Weak SSH host key algorithm: {desc}",
                    f"Server offers {algo} which uses deprecated signatures. "
                    f"Remove it from HostKeyAlgorithms in sshd_config.",
                    s.port))

        for cipher in WEAK_CIPHERS:
            if cipher in lower:
                flags.append(_flag(
                    host, Severity.HIGH, f"Weak SSH cipher: {cipher}",
                    f"Server supports {cipher} which is vulnerable to known attacks. "
                    f"Remove it from Ciphers in sshd_config.",
                    s.port))

        for mac in WEAK_MACS:
            if mac in lower:
                flags.append(_flag(
                    host, Severity.MEDIUM, f"Weak SSH MAC: {mac}",
                    f"Server supports {mac} which is considered weak. "
                    f"Remove it from MACs in sshd_config.",
                    s.port))

    return flags
