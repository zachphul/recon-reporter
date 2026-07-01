"""Shared AI contract: the output schema, the system prompt, the prompt builder,
and the grounding check that rejects any AI finding not backed by real scan data."""
from __future__ import annotations

from pydantic import BaseModel, Field

from ..model import ScanRun, Severity


class RemediationStep(BaseModel):
    action: str = Field(description="One-line summary of what to do")
    command: str | None = Field(
        default=None,
        description="Exact shell command or config snippet to execute (if applicable)",
    )
    description: str = Field(
        default="",
        description="Longer explanation of why this step matters and what to verify after",
    )


class AnalyzedFinding(BaseModel):
    title: str
    severity: Severity
    affected: str = Field(description="host or host:port this finding concerns")
    why_it_matters: str
    remediation: str
    remediation_steps: list[RemediationStep] = Field(
        default_factory=list,
        description="Ordered, actionable steps to remediate this finding",
    )
    evidence: str = Field(description="what in the scan data supports this")
    grounded: bool = True  # set by post-validation, not the model


class Analysis(BaseModel):
    executive_summary: str
    findings: list[AnalyzedFinding]
    attack_narrative: str


SYSTEM_PROMPT = (
    "You are a senior penetration-test report writer. You are given STRUCTURED recon "
    "findings (hosts, services, versions, CVEs, rule flags). Write a concise, accurate "
    "security assessment.\n"
    "RULES:\n"
    "- Ground every finding in the provided data. Do NOT invent services, ports, or CVEs.\n"
    "- Rank by real-world exploitability and business impact, not raw port count.\n"
    "- For each finding give: title, severity, affected host:port, why it matters, and a "
    "concrete remediation.\n"
    "- Provide specific, actionable remediation_steps for each finding. Each step should have:\n"
    "  - action: a one-line summary\n"
    "  - command: the exact shell command, sshd_config line, or config snippet (if applicable)\n"
    "  - description: why this step matters and what to verify after\n"
    "- Use real commands (e.g. 'sudo systemctl restart sshd', 'sudo ufw deny 23/tcp'). "
    "Do NOT use placeholder commands.\n"
    "- For CVE findings, include specific version upgrade commands or patch references.\n"
    "- Order steps from most critical to least critical.\n"
    "- If the data is thin, say so plainly rather than padding.\n"
)


def build_prompt(scan: ScanRun) -> str:
    lines = [f"TARGET: {scan.target}", f"STARTED: {scan.started_at.isoformat()}", ""]
    for h in scan.hosts:
        head = f"HOST {h.address}"
        if h.hostname:
            head += f" ({h.hostname})"
        if h.os_guess:
            head += f" — OS: {h.os_guess}"
        lines.append(head)
        for s in h.services:
            line = f"  {s.port}/{s.protocol} {s.state} {s.label}".rstrip()
            if s.cves:
                line += "  CVEs: " + ", ".join(
                    f"{c.id}({c.cvss})" if c.cvss else c.id for c in s.cves
                )
            lines.append(line)
            for sid, out in s.scripts.items():
                if out:
                    lines.append(f"      [{sid}] {out[:160]}")
    if scan.flags:
        lines.append("")
        lines.append("RULE FLAGS:")
        for f in scan.flags:
            loc = f"{f.host}:{f.port}" if f.port else f.host
            lines.append(f"  [{f.severity.value}] {f.title} @ {loc} — {f.detail}")
    return "\n".join(lines)


def ground(analysis: Analysis, scan: ScanRun) -> Analysis:
    """Mark findings whose 'affected' endpoint isn't present in the scan."""
    endpoints = scan.all_endpoints()
    for f in analysis.findings:
        host = f.affected.split(":")[0].strip()
        f.grounded = f.affected.strip() in endpoints or host in endpoints
    return analysis
