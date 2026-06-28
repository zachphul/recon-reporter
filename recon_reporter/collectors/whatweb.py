"""WhatWeb collector — web technology fingerprinting. Output is merged into the
matching HTTP/HTTPS service's scripts as a `whatweb` entry."""
from __future__ import annotations

import json

from ..model import Host
from .base import Collector, RawOutput


class WhatWebCollector(Collector):
    name = "whatweb"
    binary = "whatweb"

    def run(self, target: str, timeout: int = 180) -> RawOutput:
        args = [self.binary, "--quiet", "--log-json=-", "--no-errors", target]
        try:
            _, out, err = self._exec(args, timeout)
        except FileNotFoundError:
            return RawOutput(self.name, False, "", error="whatweb not installed")
        if not out.strip():
            return RawOutput(self.name, False, "", error=err.strip() or "no output")
        return RawOutput(self.name, True, out)


def merge_into_hosts(raw: str, hosts: list[Host]) -> int:
    """Attach whatweb plugin summary to the http/https service of each host. Returns merges."""
    merged = 0
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    for ent in entries:
        plugins = ent.get("plugins", {})
        if not plugins:
            continue
        summary = ", ".join(sorted(plugins.keys()))[:300]
        for h in hosts:
            for s in h.services:
                if s.service in ("http", "https") or s.port in (80, 443, 8080, 8443):
                    s.scripts["whatweb"] = summary
                    merged += 1
    return merged
