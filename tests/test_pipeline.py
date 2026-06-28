"""Tests for the offline pipeline: parse -> rules -> report. No network, no nmap."""
from datetime import datetime
from pathlib import Path

from recon_reporter.auth.scope import Scope
from recon_reporter.enrich import rules
from recon_reporter.model import ScanRun, Severity
from recon_reporter.parsers.nmap_xml import parse_nmap_xml
from recon_reporter.report import markdown as md

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def _hosts():
    return parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))


def test_parses_hosts_and_services():
    hosts = _hosts()
    assert len(hosts) == 1
    h = hosts[0]
    assert h.address == "45.33.32.156"
    assert h.hostname == "scanme.nmap.org"
    assert "Linux" in (h.os_guess or "")
    ports = {s.port for s in h.services}
    assert ports == {22, 23, 80, 443}
    ssh = next(s for s in h.services if s.port == 22)
    assert ssh.product == "OpenSSH"
    assert "6.6.1p1" in (ssh.version or "")


def test_rules_flag_telnet_and_weak_tls():
    flags = rules.evaluate(_hosts())
    titles = [f.title for f in flags]
    assert any("Telnet" in t for t in titles)
    assert any("TLS" in t for t in titles)
    assert any(f.severity == Severity.HIGH for f in flags)  # telnet is HIGH


def test_report_renders_without_ai():
    hosts = _hosts()
    run = ScanRun(target="scanme.nmap.org", started_at=datetime.now(), hosts=hosts)
    run.flags = rules.evaluate(hosts)
    report = md.render(run, analysis=None)
    assert "# Security Assessment" in report
    assert "Authorized testing only" in report
    assert "Telnet" in report


def test_scope_gate_blocks_unlisted_target():
    sc = Scope(["scanme.nmap.org", "127.0.0.1"])
    assert sc.authorizes("127.0.0.1") is True
    assert sc.authorizes("8.8.8.8") is False
