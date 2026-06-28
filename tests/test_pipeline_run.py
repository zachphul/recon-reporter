"""Tests for the extracted pipeline — offline path and the nmap-missing error path."""
from pathlib import Path

import pytest

import recon_reporter.pipeline as pl
from recon_reporter.pipeline import PipelineError, PipelineResult, run_pipeline

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def test_pipeline_offline_no_ai():
    xml = FIXTURE.read_text(encoding="utf-8")
    raws: dict[str, str] = {}
    res = run_pipeline(
        "scanme.nmap.org",
        offline_xml=xml,
        no_ai=True,
        raw_sink=lambda tool, raw: raws.__setitem__(tool, raw),
    )
    assert isinstance(res, PipelineResult)
    assert res.analysis is None
    assert len(res.scan.hosts) == 1
    assert len(res.scan.flags) > 0
    assert res.scan.finished_at is not None
    assert raws.get("nmap") == xml                       # raw_sink received the XML
    assert res.scan.tool_versions["nmap"] == "offline"


def test_pipeline_live_without_nmap_raises(monkeypatch):
    monkeypatch.setattr(pl.NmapCollector, "available", lambda self: False)
    with pytest.raises(PipelineError):
        run_pipeline("scanme.nmap.org", no_ai=True)
