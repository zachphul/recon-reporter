"""Tests for bug bounty scope parser and report format."""
import json
from datetime import datetime
from pathlib import Path

import pytest

from recon_reporter.auth.bugbounty import BugBountyScope
from recon_reporter.model import Host, RuleFlag, ScanRun, Service, Severity
from recon_reporter.report.bugbounty import SEVERITY_MAP, to_bugbounty_json


def _make_scope_file(tmp_path: Path, data: dict) -> Path:
    import yaml
    p = tmp_path / "scope.yml"
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


def test_scope_authorizes_exact_match(tmp_path):
    p = _make_scope_file(tmp_path, {
        "in_scope": ["example.com", "203.0.113.0/24"],
    })
    scope = BugBountyScope.load(p)
    assert scope.authorizes("example.com") is True
    assert scope.authorizes("evil.com") is False


def test_scope_authorizes_wildcard(tmp_path):
    p = _make_scope_file(tmp_path, {
        "in_scope": ["*.example.com"],
    })
    scope = BugBountyScope.load(p)
    assert scope.authorizes("app.example.com") is True
    assert scope.authorizes("api.example.com") is True
    assert scope.authorizes("example.com") is False
    assert scope.authorizes("evil.com") is False


def test_scope_respects_exclusions(tmp_path):
    p = _make_scope_file(tmp_path, {
        "in_scope": ["*.example.com"],
        "out_of_scope": ["admin.example.com", "internal.example.com"],
    })
    scope = BugBountyScope.load(p)
    assert scope.authorizes("app.example.com") is True
    assert scope.authorizes("admin.example.com") is False
    assert scope.authorizes("internal.example.com") is False


def test_scope_require_raises_on_unauthorized(tmp_path):
    p = _make_scope_file(tmp_path, {"in_scope": ["example.com"]})
    scope = BugBountyScope.load(p)
    with pytest.raises(Exception, match="not covered"):
        scope.require("evil.com", acknowledged=True)
    with pytest.raises(Exception, match="--authorized"):
        scope.require("example.com", acknowledged=False)


def test_scope_require_raises_on_excluded(tmp_path):
    p = _make_scope_file(tmp_path, {
        "in_scope": ["*.example.com"],
        "out_of_scope": ["admin.example.com"],
    })
    scope = BugBountyScope.load(p)
    with pytest.raises(Exception, match="OUT OF SCOPE"):
        scope.require("admin.example.com", acknowledged=True)


def test_scope_summary(tmp_path):
    p = _make_scope_file(tmp_path, {
        "program_name": "Test Program",
        "program_url": "https://example.com/bb",
        "rules_url": "https://example.com/rules",
        "in_scope": ["*.example.com", "10.0.0.0/8"],
        "out_of_scope": ["admin.example.com"],
    })
    scope = BugBountyScope.load(p)
    s = scope.summary()
    assert "Test Program" in s
    assert "*.example.com" in s
    assert "admin.example.com" in s


def test_scope_loads_from_json(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "in_scope": ["test.com"],
        "out_of_scope": ["old.test.com"],
    }), encoding="utf-8")
    scope = BugBountyScope.load(p)
    assert scope.authorizes("test.com") is True
    assert scope.authorizes("old.test.com") is False


def test_bugbounty_report_format():
    run = ScanRun(
        target="app.example.com",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        finished_at=datetime(2026, 1, 1, 12, 5, 0),
        hosts=[Host(address="203.0.113.1", services=[
            Service(port=22, service="ssh", product="OpenSSH", version="8.9"),
        ])],
        flags=[RuleFlag(
            title="Telnet exposed", severity=Severity.HIGH,
            detail="Telnet on port 23", host="203.0.113.1", port=23,
        )],
        tool_versions={"nmap": "7.94"},
    )
    report = json.loads(to_bugbounty_json(
        run, None,
        program_name="Test Program",
        program_url="https://example.com/bb",
    ))
    assert report["report_type"] == "reconlens"
    assert report["target"] == "app.example.com"
    assert report["program"]["name"] == "Test Program"
    assert len(report["findings"]) == 1
    f = report["findings"][0]
    assert f["title"] == "Telnet exposed"
    assert f["severity"] == "High"
    assert "bugcrowd" in f["platform_ratings"]
    assert "hackerone" in f["platform_ratings"]
    assert "intigriti" in f["platform_ratings"]
    assert len(f["reproduction_steps"]) >= 2
    assert "impact" in f


def test_bugbounty_report_with_ai_analysis():
    from recon_reporter.ai.base import Analysis, AnalyzedFinding, RemediationStep
    run = ScanRun(target="x", started_at=datetime.now())
    analysis = Analysis(
        executive_summary="Test summary",
        attack_narrative="Test narrative",
        findings=[AnalyzedFinding(
            title="Weak SSH", severity=Severity.MEDIUM,
            affected="1.2.3.4:22", why_it_matters="Weak algorithms",
            remediation="Update sshd_config",
            remediation_steps=[
                RemediationStep(action="Update ciphers", command="sudo sed -i ..."),
            ],
            evidence="ssh2-enum-algorithms output",
        )],
    )
    report = json.loads(to_bugbounty_json(run, analysis))
    assert len(report["findings"]) == 1
    f = report["findings"][0]
    assert "remediation_steps" in f
    assert f["remediation_steps"][0]["command"] == "sudo sed -i ..."


def test_severity_mapping_completeness():
    for sev in Severity:
        assert sev in SEVERITY_MAP
        entry = SEVERITY_MAP[sev]
        assert "cvss_range" in entry
        assert "bugcrowd" in entry
        assert "hackerone" in entry
        assert "intigriti" in entry
        assert "label" in entry
