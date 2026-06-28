"""Local analyst — talks to an OpenAI-compatible endpoint (LM Studio / Ollama).
Free and offline. Requests JSON matching the Analysis schema and validates it."""
from __future__ import annotations

import json
import re

import httpx

from ..model import ScanRun
from .base import Analysis, SYSTEM_PROMPT, build_prompt, ground


def _extract_json(text: str) -> str:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence:
        return fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    return text[start : end + 1] if start != -1 and end != -1 else text


class LocalAnalyst:
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def analyze(self, scan: ScanRun) -> Analysis:
        schema = json.dumps(Analysis.model_json_schema())
        user = (
            build_prompt(scan)
            + "\n\nReturn ONLY a JSON object matching this schema (no prose, no markdown):\n"
            + schema
        )
        r = httpx.post(
            f"{self.base_url}/chat/completions",
            json={
                "model": self.model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
            },
            timeout=240,
        )
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        analysis = Analysis.model_validate_json(_extract_json(content))
        return ground(analysis, scan)
