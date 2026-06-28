"""AI-layer tests — local analyst JSON-repair retry. No real model, httpx mocked."""
import json
from datetime import datetime

import recon_reporter.ai.local as localmod
from recon_reporter.ai.local import LocalAnalyst
from recon_reporter.model import ScanRun

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
