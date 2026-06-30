"""AI-layer tests — local analyst JSON-repair retry. No real model, httpx mocked."""
import json
from datetime import datetime

import recon_reporter.ai.local as localmod
from recon_reporter.ai.base import Analysis, AnalyzedFinding, ground
from recon_reporter.ai.local import LocalAnalyst
from recon_reporter.model import Host, ScanRun, Service, Severity


def test_grounding_accepts_hostname_or_ip():
    run = ScanRun(target="t", started_at=datetime.now(), hosts=[
        Host(address="1.2.3.4", hostname="web.example", services=[Service(port=80)]),
    ])
    a = Analysis(executive_summary="", attack_narrative="", findings=[
        AnalyzedFinding(title="by hostname", severity=Severity.LOW, affected="web.example:80",
                        why_it_matters="", remediation="", evidence=""),
        AnalyzedFinding(title="by ip", severity=Severity.LOW, affected="1.2.3.4:80",
                        why_it_matters="", remediation="", evidence=""),
        AnalyzedFinding(title="invented", severity=Severity.LOW, affected="9.9.9.9:443",
                        why_it_matters="", remediation="", evidence=""),
    ])
    ground(a, run)
    assert a.findings[0].grounded is True   # hostname form now recognised
    assert a.findings[1].grounded is True   # ip form
    assert a.findings[2].grounded is False  # not in scan -> flagged

_VALID = json.dumps({
    "executive_summary": "Summary.",
    "findings": [{
        "title": "Telnet exposed", "severity": "high", "affected": "1.2.3.4:23",
        "why_it_matters": "cleartext", "remediation": "use ssh", "evidence": "port 23 open",
    }],
    "attack_narrative": "Narrative.",
})


class _Resp:
    def __init__(self, content):
        self._c = content

    def raise_for_status(self):
        return None

    def json(self):
        return {"choices": [{"message": {"content": self._c}}]}


def test_local_analyst_repairs_bad_json(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Resp("Sure! Here's your analysis (but no actual JSON object).")
        return _Resp("```json\n" + _VALID + "\n```")

    monkeypatch.setattr(localmod.httpx, "post", fake_post)
    run = ScanRun(target="x", started_at=datetime.now())
    analysis = LocalAnalyst("http://localhost:1234/v1", "m").analyze(run)
    assert calls["n"] == 2  # repaired on the second attempt
    assert analysis.findings[0].severity.value == "high"


def test_local_analyst_first_try_ok(monkeypatch):
    def fake_post(url, **kw):
        return _Resp(_VALID)

    monkeypatch.setattr(localmod.httpx, "post", fake_post)
    run = ScanRun(target="x", started_at=datetime.now())
    analysis = LocalAnalyst("http://localhost:1234/v1", "m").analyze(run)
    assert analysis.findings[0].title == "Telnet exposed"
