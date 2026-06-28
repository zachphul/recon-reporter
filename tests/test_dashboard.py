"""Dashboard aggregation tests. No network."""
from datetime import datetime

from recon_reporter.dashboard import build_dashboard
from recon_reporter.model import ScanRun


def test_dashboard_empty(tmp_path):
    out = build_dashboard(tmp_path)
    assert "No runs found" in out


def test_dashboard_lists_runs(tmp_path):
    d = tmp_path / "host.example-20260101-000000"
    d.mkdir()
    run = ScanRun(target="host.example", started_at=datetime.now())
    (d / "findings.json").write_text(run.model_dump_json(), encoding="utf-8")
    out = build_dashboard(tmp_path)
    assert out.startswith("<!DOCTYPE html>")
    assert "host.example" in out
    assert "report.html" in out  # link to the run's report
