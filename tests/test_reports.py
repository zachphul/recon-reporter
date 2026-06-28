"""Report edge-case tests — empty scans must still render valid output, not crash."""
import json
from datetime import datetime

from recon_reporter.model import ScanRun
from recon_reporter.report import html as htmlrep
from recon_reporter.report import markdown as md
from recon_reporter.report import sarif


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
