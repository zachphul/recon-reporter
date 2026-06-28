"""Runtime configuration, resolved from env with sane defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    # AI provider: "auto" picks Claude when ANTHROPIC_API_KEY is set, else local.
    provider: str = os.getenv("RR_PROVIDER", "auto")
    claude_model: str = os.getenv("RR_CLAUDE_MODEL", "claude-opus-4-8")
    local_base_url: str = os.getenv("RR_LOCAL_URL", "http://localhost:1234/v1")
    local_model: str = os.getenv("RR_LOCAL_MODEL", "local-model")
    nvd_api_key: str | None = os.getenv("NVD_API_KEY")

    def resolved_provider(self) -> str:
        if self.provider != "auto":
            return self.provider
        return "claude" if os.getenv("ANTHROPIC_API_KEY") else "local"


settings = Settings()
