"""Nmap collector — service/version detection + default scripts, XML to stdout."""
from __future__ import annotations

import re
import subprocess

from .base import Collector, RawOutput

PROFILES = {
    # non-intrusive default: top 1000 ports, service+version, default safe scripts
    "default": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
    "quick": ["-sV", "-T4", "-F"],
    "full": ["-sV", "-sC", "-T4", "-p-"],
}


class NmapCollector(Collector):
    name = "nmap"
    binary = "nmap"

    def __init__(self, profile: str = "default"):
        self.profile = profile if profile in PROFILES else "default"

    def version(self) -> str | None:
        try:
            _, out, _ = self._exec([self.binary, "--version"], timeout=15)
            m = re.search(r"Nmap version ([\d.]+)", out)
            return m.group(1) if m else None
        except Exception:
            return None

    def run(self, target: str, timeout: int = 600) -> RawOutput:
        args = [self.binary, *PROFILES[self.profile], "-oX", "-", target]
        try:
            _, out, err = self._exec(args, timeout)
        except FileNotFoundError:
            return RawOutput(self.name, False, "", error="nmap not installed")
        except subprocess.TimeoutExpired:
            return RawOutput(self.name, False, "", error=f"timed out after {timeout}s")
        if not out.strip():
            return RawOutput(self.name, False, "", version=self.version(),
                             error=err.strip() or "no output")
        return RawOutput(self.name, True, out, version=self.version())
