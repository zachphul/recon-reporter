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
    base = f"{_slug(target)}-{ts}"
    d = Path(root) / base
    n = 1
    while d.exists():  # avoid clobbering a run created in the same second
        d = Path(root) / f"{base}-{n}"
        n += 1
    (d / "raw").mkdir(parents=True, exist_ok=True)
    return d


def save_raw(run_dir: Path, tool: str, raw: str) -> None:
    (run_dir / "raw" / f"{tool}.txt").write_text(raw, encoding="utf-8")


def save_findings(run_dir: Path, scan: ScanRun) -> None:
    (run_dir / "findings.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


def iter_run_dirs(root: str | Path = "runs") -> list[Path]:
    """All run directories under `root` that contain a findings.json, oldest first by name."""
    rp = Path(root)
    if not rp.exists():
        return []
    dirs = [d for d in rp.iterdir() if d.is_dir() and (d / "findings.json").exists()]
    return sorted(dirs, key=lambda d: d.name)


def latest_findings(target: str, root: str | Path = "runs") -> Path | None:
    """Most recent findings.json for `target`, or None if there's no prior run."""
    slug = _slug(target)
    cands = [d for d in iter_run_dirs(root) if d.name.startswith(slug + "-")]
    return (cands[-1] / "findings.json") if cands else None


def save_report(run_dir: Path, markdown: str) -> Path:
    p = run_dir / "report.md"
    p.write_text(markdown, encoding="utf-8")
    return p


def save_html(run_dir: Path, html: str) -> Path:
    p = run_dir / "report.html"
    p.write_text(html, encoding="utf-8")
    return p


def save_sarif(run_dir: Path, sarif: str) -> Path:
    p = run_dir / "report.sarif.json"
    p.write_text(sarif, encoding="utf-8")
    return p


def save_csv(run_dir: Path, csv_text: str) -> Path:
    p = run_dir / "findings.csv"
    p.write_text(csv_text, encoding="utf-8")
    return p
