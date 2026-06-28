"""Persist each run to a timestamped directory: raw output, structured JSON, report."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .model import ScanRun


def _slug(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)[:60]


def make_run_dir(target: str, root: str | Path = "runs") -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    d = Path(root) / f"{_slug(target)}-{ts}"
    (d / "raw").mkdir(parents=True, exist_ok=True)
    return d


def save_raw(run_dir: Path, tool: str, raw: str) -> None:
    (run_dir / "raw" / f"{tool}.txt").write_text(raw, encoding="utf-8")


def save_findings(run_dir: Path, scan: ScanRun) -> None:
    (run_dir / "findings.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


def save_report(run_dir: Path, markdown: str) -> Path:
    p = run_dir / "report.md"
    p.write_text(markdown, encoding="utf-8")
    return p
