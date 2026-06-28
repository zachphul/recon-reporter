"""Provider factory — returns a ClaudeAnalyst or LocalAnalyst based on settings."""
from __future__ import annotations

from typing import Protocol

from ..config import Settings, settings as default_settings
from ..model import ScanRun
from .base import Analysis


class Analyst(Protocol):
    def analyze(self, scan: ScanRun) -> Analysis: ...


def get_analyst(settings: Settings | None = None) -> Analyst:
    s = settings or default_settings
    provider = s.resolved_provider()
    if provider == "claude":
        from .claude import ClaudeAnalyst

        return ClaudeAnalyst(model=s.claude_model)
    from .local import LocalAnalyst

    return LocalAnalyst(base_url=s.local_base_url, model=s.local_model)
