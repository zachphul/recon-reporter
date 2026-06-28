"""Claude analyst — uses the official Anthropic SDK with structured outputs.
Imported lazily so the package works without `anthropic` installed when using --local."""
from __future__ import annotations

from ..model import ScanRun
from .base import SYSTEM_PROMPT, Analysis, build_prompt, ground


class ClaudeAnalyst:
    def __init__(self, model: str = "claude-opus-4-8"):
        import anthropic  # lazy

        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        self.model = model

    def analyze(self, scan: ScanRun) -> Analysis:
        resp = self.client.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_prompt(scan)}],
            output_format=Analysis,
        )
        analysis = resp.parsed_output
        if analysis is None:
            raise RuntimeError("Claude returned no parseable structured output")
        return ground(analysis, scan)
