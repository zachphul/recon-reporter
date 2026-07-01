"""Canonical data model. Every collector parses into these types; the AI layer and
report renderer only ever read from here — never from raw tool output."""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class CveRef(BaseModel):
    id: str
    cvss: float | None = None
    summary: str | None = None
    # Exploit intelligence (populated by enrich.exploit when --cve is used):
    epss: float | None = None            # 0-1 probability of exploitation in the next 30 days
    epss_percentile: float | None = None  # 0-1 rank of this CVE among all scored CVEs
    kev: bool = False                     # listed in CISA's Known Exploited Vulnerabilities catalog
    ransomware: bool = False              # KEV entry linked to known ransomware campaign use

    @property
    def priority(self) -> tuple[int, float, float]:
        """Sort key (descending = most urgent): a CVE known to be actively exploited (KEV)
        always outranks one that merely has a high CVSS. Within each tier, rank by real-world
        exploitation likelihood (EPSS), then by CVSS severity."""
        return (1 if self.kev else 0, self.epss or 0.0, self.cvss or 0.0)


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    scripts: dict[str, str] = Field(default_factory=dict)
    cves: list[CveRef] = Field(default_factory=list)

    @property
    def label(self) -> str:
        bits = [self.service or "?", self.product or "", self.version or ""]
        return " ".join(b for b in bits if b).strip()


class Host(BaseModel):
    address: str
    hostname: str | None = None
    os_guess: str | None = None
    state: str = "up"
    services: list[Service] = Field(default_factory=list)


class RuleFlag(BaseModel):
    """A deterministic, rule-based observation (not AI-generated)."""
    title: str
    severity: Severity
    detail: str
    host: str
    port: int | None = None


class ScanRun(BaseModel):
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    hosts: list[Host] = Field(default_factory=list)
    flags: list[RuleFlag] = Field(default_factory=list)
    risk_score: int | None = None
    risk_breakdown: dict[str, int] = Field(default_factory=dict)

    def all_endpoints(self) -> set[str]:
        """host / host:port strings present in this scan — used to ground AI findings.
        Includes both the IP address and the hostname so a finding referencing either
        form is recognised as grounded."""
        out: set[str] = set()
        for h in self.hosts:
            names = [h.address] + ([h.hostname] if h.hostname else [])
            out.update(names)
            for s in h.services:
                for n in names:
                    out.add(f"{n}:{s.port}")
        return out
