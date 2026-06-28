"""Tests for Phase 2 features: HTML report, scan diff, collector merges. No network."""
from datetime import datetime
from pathlib import Path

from recon_reporter.parsers.nmap_xml import parse_nmap_xml
from recon_reporter.model import ScanRun, Host, Service
from recon_reporter.report import html as htmlrep
from recon_reporter import diff as diffmod
from recon_reporter.collectors import whatweb, tls

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def _run():
    run = ScanRun(target="scanme.nmap.org", started_at=datetime.now())
    run.hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    return run


def test_html_report_renders():
    out = htmlrep.render(_run(), analysis=None)
    assert out.startswith("<!DOCTYPE html>")
    assert "scanme.nmap.org" in out
    assert "Severity summary" in out
    assert "Telnet" not in out or "telnet" in out.lower()  # service table present


def test_diff_detects_opened_and_closed():
    old = _run()
    new = _run()
    # close port 23, open a new 8080
    new.hosts[0].services = [s for s in new.hosts[0].services if s.port != 23]
    new.hosts[0].services.append(Service(port=8080, service="http-proxy"))
    d = diffmod.diff_runs(old, new)
    eps_opened = [x["endpoint"] for x in d["opened"]]
    eps_closed = [x["endpoint"] for x in d["closed"]]
    assert any(e.endswith(":8080") for e in eps_opened)
    assert any(e.endswith(":23") for e in eps_closed)
    md = diffmod.render_markdown(d)
    assert "Scan diff" in md


def test_whatweb_merge():
    hosts = [Host(address="1.2.3.4", services=[Service(port=80, service="http")])]
    raw = '{"target":"http://1.2.3.4","plugins":{"Apache":{},"PHP":{},"jQuery":{}}}'
    n = whatweb.merge_into_hosts(raw, hosts)
    assert n == 1
    assert "Apache" in hosts[0].services[0].scripts["whatweb"]


def test_tls_merge_flags_weak_proto():
    hosts = [Host(address="1.2.3.4", services=[Service(port=443, service="https")])]
    raw = "SSLv3       enabled\nTLSv1.0   enabled\nTLSv1.2   enabled"
    n = tls.merge_into_hosts(raw, hosts)
    assert n == 1
    assert "SSLv3" in hosts[0].services[0].scripts["sslscan"]
