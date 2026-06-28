"""HTTP security-header collector. Pure-Python (httpx) — no external tool, so it runs
anywhere, not just Kali. Fetches each web endpoint and grades its security headers."""
from __future__ import annotations

import httpx

from ..logconf import get_logger
from ..model import Host, RuleFlag, Severity

log = get_logger(__name__)

# header -> (finding title, severity) when MISSING
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS header missing", Severity.MEDIUM),
    "content-security-policy": ("Content-Security-Policy missing", Severity.MEDIUM),
    "x-frame-options": ("X-Frame-Options missing (clickjacking risk)", Severity.LOW),
    "x-content-type-options": ("X-Content-Type-Options missing (MIME sniffing)", Severity.LOW),
    "referrer-policy": ("Referrer-Policy missing", Severity.INFO),
    "permissions-policy": ("Permissions-Policy missing", Severity.INFO),
}


def grade(headers, host: str, port: int) -> list[RuleFlag]:
    """Pure: given a header mapping, return rule flags for missing/risky headers."""
    present = {str(k).lower() for k in headers}
    flags: list[RuleFlag] = []
    for h, (title, sev) in SECURITY_HEADERS.items():
        if h not in present:
            flags.append(RuleFlag(title=title, severity=sev,
                                  detail=f"HTTP response is missing the `{h}` header.",
                                  host=host, port=port))
    server = None
    for k in headers:
        if str(k).lower() == "server":
            server = headers[k]
            break
    if server:
        flags.append(RuleFlag(title=f"Server header discloses '{server}'", severity=Severity.INFO,
                              detail="Server software/version is advertised in responses.",
                              host=host, port=port))
    return flags


class HttpHeaderCollector:
    name = "http-headers"

    def __init__(self, verify: bool = True):
        # verify=True by default (safe). Recon often targets hosts with self-signed/expired
        # certs; pass verify=False (CLI --insecure) to reach them, accepting MITM risk.
        self.verify = verify

    def collect(self, hosts: list[Host], timeout: int = 15) -> list[RuleFlag]:
        flags: list[RuleFlag] = []
        for h in hosts:
            for s in h.services:
                is_web = s.service in ("http", "https") or s.port in (80, 443, 8080, 8443)
                if not is_web:
                    continue
                scheme = "https" if (s.service == "https" or s.port in (443, 8443)) else "http"
                url = f"{scheme}://{h.address}:{s.port}/"
                try:
                    r = httpx.get(url, timeout=timeout, verify=self.verify,
                                  follow_redirects=True)
                except Exception as e:  # noqa: BLE001 - report and continue to next endpoint
                    log.warning("header fetch failed for %s: %s", url, e)
                    continue
                s.scripts["http-headers"] = "; ".join(
                    f"{k}:{v}" for k, v in r.headers.items()
                )[:400]
                flags.extend(grade(r.headers, h.address, s.port))
        return flags
