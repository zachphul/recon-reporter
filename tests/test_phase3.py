"""Phase 3 tests: HTTP security-header grading + SARIF export. Fully offline."""
from datetime import datetime
from pathlib import Path

from recon_reporter.collectors.http_headers import grade
from recon_reporter.enrich import rules
from recon_reporter.model import ScanRun
from recon_reporter.parsers.nmap_xml import parse_nmap_xml
from recon_reporter.report import sarif as sarifrep

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def test_header_grading_flags_missing():
    headers = {"Server": "nginx/1.18", "Content-Type": "text/html"}
    flags = grade(headers, "1.2.3.4", 443)
    titles = [f.title for f in flags]
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("discloses" in t for t in titles)  # Server header disclosure


def test_header_grading_clean_when_present():
    headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    flags = grade(headers, "1.2.3.4", 443)
    # no Server header, all security headers present -> no flags
    assert flags == []


def test_sarif_is_valid_shape():
    run = ScanRun(target="scanme.nmap.org", started_at=datetime.now())
    run.hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    run.flags = rules.evaluate(run.hosts)
    doc = sarifrep.to_sarif(run, analysis=None)
    assert doc["version"] == "2.1.0"
    runs = doc["runs"]
    assert runs[0]["tool"]["driver"]["name"] == "Recon Reporter"
    assert len(runs[0]["results"]) == len(run.flags)
    levels = {r["level"] for r in runs[0]["results"]}
    assert levels <= {"error", "warning", "note"}
