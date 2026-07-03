"""Report edge-case tests — empty scans must still render valid output, not crash."""
import json
from datetime import datetime
from pathlib import Path

from recon_reporter.enrich import rules
from recon_reporter.model import CveRef, Host, ScanRun, Service
from recon_reporter.parsers.nmap_xml import parse_nmap_xml
from recon_reporter.report import csv as csvrep
from recon_reporter.report import html as htmlrep
from recon_reporter.report import markdown as md
from recon_reporter.report import sarif

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def _empty():
    return ScanRun(target="nothing-found", started_at=datetime.now())


def _scan_with_kev():
    return ScanRun(target="t", started_at=datetime.now(), hosts=[
        Host(address="10.0.0.1", services=[Service(port=443, service="https", cves=[
            CveRef(id="CVE-2021-44228", cvss=10.0, kev=True, ransomware=True, epss=0.98),
            CveRef(id="CVE-2020-1234", cvss=9.8, epss=0.62),
        ])]),
    ])


def test_empty_scan_markdown():
    out = md.render(_empty(), None)
    assert "# Security Assessment" in out
    assert "Authorized testing only" in out


def test_markdown_priority_section_present_with_exploit_intel():
    out = md.render(_scan_with_kev(), None)
    assert "Exploitation priority" in out
    assert "CVE-2021-44228" in out
    assert "Actively exploited" in out
    assert "98%" in out  # EPSS rendered as a percentage


def test_markdown_priority_section_absent_without_intel():
    # A plain scan (no KEV/EPSS on any CVE) must not render the priority section.
    out = md.render(_empty(), None)
    assert "Exploitation priority" not in out


def test_html_cve_cell_shows_kev_badge():
    out = htmlrep.render(_scan_with_kev(), None)
    assert "class='kev'" in out
    assert "CVE-2021-44228" in out


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


def test_terminal_findings_table():
    from recon_reporter.report import terminal
    run = ScanRun(target="x", started_at=datetime.now())
    run.hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    run.flags = rules.evaluate(run.hosts)
    assert terminal.findings_table(run).row_count == len(run.flags)
    assert terminal.findings_table(_empty()).row_count == 1  # placeholder row
