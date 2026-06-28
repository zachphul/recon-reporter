"""Local analyst — talks to an OpenAI-compatible endpoint (LM Studio / Ollama).
Free and offline. Requests JSON matching the Analysis schema and validates it."""
from __future__ import annotations

import json
import re

import httpx

from ..logconf import get_logger
from ..model import ScanRun
from .base import SYSTEM_PROMPT, Analysis, build_prompt, ground

log = get_logger(__name__)


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

    def _chat(self, user: str) -> str:
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
        return r.json()["choices"][0]["message"]["content"]

    def analyze(self, scan: ScanRun) -> Analysis:
        schema = json.dumps(Analysis.model_json_schema())
        base = (
            build_prompt(scan)
            + "\n\nReturn ONLY a JSON object matching this schema (no prose, no markdown):\n"
            + schema
        )
        content = self._chat(base)
        try:
            analysis = Analysis.model_validate_json(_extract_json(content))
        except Exception:
            # One repair attempt — local models often wrap JSON in prose on the first try.
            log.warning("local model returned invalid JSON; retrying once with a stricter prompt")
            repair = ("\n\nYour previous response was not valid JSON for the schema. "
                      "Respond with ONLY the JSON object, no prose, no code fences.")
            content = self._chat(base + repair)
            analysis = Analysis.model_validate_json(_extract_json(content))
        return ground(analysis, scan)
