"""Tests for the deterministic rule engine, including outdated-version detection."""
from pathlib import Path

from recon_reporter.enrich import rules
from recon_reporter.enrich.rules import _ver_tuple
from recon_reporter.model import Severity
from recon_reporter.parsers.nmap_xml import parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def test_ver_tuple():
    assert _ver_tuple("6.6.1p1") == (6, 6, 1)
    assert _ver_tuple("2.4.7") == (2, 4, 7)
    assert _ver_tuple("") == ()
    assert _ver_tuple("nope") == ()


def test_outdated_software_flagged():
    hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    flags = rules.evaluate(hosts)
    outdated = [f for f in flags if "outdated" in f.title.lower()]
    # OpenSSH 6.6.1 (< 9.0) and Apache httpd 2.4.7 (< 2.4.60) should both flag
    assert any("OpenSSH" in t for t in [f.title for f in outdated])
    assert any("Apache" in t for t in [f.title for f in outdated])
    assert all(f.severity == Severity.MEDIUM for f in outdated)
