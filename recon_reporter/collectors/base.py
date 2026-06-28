"""Collector interface. Add a new recon tool by subclassing Collector; the
orchestrator discovers and runs whatever is registered and available."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class RawOutput:
    tool: str
    ok: bool
    raw: str
    version: str | None = None
    error: str | None = None


class Collector:
    name: str = "collector"
    binary: str = ""

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def version(self) -> str | None:
        return None

    def run(self, target: str, timeout: int = 600) -> RawOutput:  # pragma: no cover
        raise NotImplementedError

    # helper for subclasses
    def _exec(self, args: list[str], timeout: int) -> tuple[int, str, str]:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
