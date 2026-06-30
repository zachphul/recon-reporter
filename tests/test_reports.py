"""Report edge-case tests — empty scans must still render valid output, not crash."""
import json
from datetime import datetime
from pathlib import Path

from recon_reporter.enrich import rules
from recon_reporter.model import ScanRun
from recon_reporter.parsers.nmap_xml import parse_nmap_xml
from recon_reporter.report import csv as csvrep
from recon_reporter.report import html as htmlrep
from recon_reporter.report import markdown as md
from recon_reporter.report import sarif

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def _empty():
    return ScanRun(target="nothing-found", started_at=datetime.now())


def test_empty_scan_markdown():
    out = md.render(_empty(), None)
    assert "# Security Assessment" in out
    assert "Authorized testing only" in out


def test_empty_scan_html():
    out = htmlrep.render(_empty(), None)
    assert out.startswith("<!DOCTYPE html>")
    assert out.rstrip().endswith("</html>")


def test_empty_scan_sarif_has_no_results():
    doc = json.loads(sarif.dumps(_empty(), None))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_pdf_degrades_gracefully(tmp_path):
    from recon_reporter.report import pdf
    out = tmp_path / "x.pdf"
    ok = pdf.to_pdf("<html><body>ok</body></html>", out)
    # weasyprint may or may not be present; either way no crash, and result is consistent.
    assert ok is (out.exists())


def test_csv_export_rows_match_flags():
    run = ScanRun(target="x", started_at=datetime.now())
    run.hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    run.flags = rules.evaluate(run.hosts)
    out = csvrep.to_csv(run, None)
    lines = out.strip().splitlines()
    assert lines[0] == "severity,title,affected,detail,source"
    assert len(lines) == len(run.flags) + 1   # header + one row per flag
    assert "telnet" in out.lower()
    # severity-ranked: first data row is the highest severity present
    assert lines[1].split(",")[0] in {"critical", "high"}
