"""TLS collector — sslscan. Output is merged into the matching service's scripts as
`sslscan`; the rules engine already detects deprecated-protocol markers in script text."""
from __future__ import annotations

import re

from ..model import Host
from .base import Collector, RawOutput

_PROTO_RE = re.compile(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)",
                       re.IGNORECASE)


class TlsCollector(Collector):
    name = "sslscan"
    binary = "sslscan"

    def run(self, target: str, timeout: int = 120) -> RawOutput:
        args = [self.binary, "--no-colour", target]
        try:
            _, out, err = self._exec(args, timeout)
        except FileNotFoundError:
            return RawOutput(self.name, False, "", error="sslscan not installed")
        if not out.strip():
            return RawOutput(self.name, False, "", error=err.strip() or "no output")
        return RawOutput(self.name, True, out)


def merge_into_hosts(raw: str, hosts: list[Host]) -> int:
    """Summarize enabled protocols and attach to TLS-bearing services."""
    enabled = [m.group(1) for m in _PROTO_RE.finditer(raw) if m.group(2).lower() == "enabled"]
    if not enabled:
        return 0
    summary = "Enabled protocols: " + ", ".join(sorted(set(enabled)))
    merged = 0
    for h in hosts:
        for s in h.services:
            if s.service in ("https", "ssl", "tls") or s.port in (443, 8443, 993, 995):
                s.scripts["sslscan"] = summary
                merged += 1
    return merged
