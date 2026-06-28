"""Store helpers — run-dir uniqueness and latest_findings lookup."""
from datetime import datetime

from recon_reporter import store
from recon_reporter.model import ScanRun


def _seed(root, target, ts):
    d = root / f"{store._slug(target)}-{ts}"
    d.mkdir(parents=True)
    run = ScanRun(target=target, started_at=datetime.now())
    (d / "findings.json").write_text(run.model_dump_json(), encoding="utf-8")
    return d


def test_latest_findings_picks_newest(tmp_path):
    _seed(tmp_path, "host.example", "20260101-000000")
    newer = _seed(tmp_path, "host.example", "20260102-000000")
    _seed(tmp_path, "other.example", "20260103-000000")
    assert store.latest_findings("host.example", tmp_path) == newer / "findings.json"
    assert store.latest_findings("missing.example", tmp_path) is None


def test_make_run_dir_no_collision(tmp_path):
    a = store.make_run_dir("x", tmp_path)
    b = store.make_run_dir("x", tmp_path)  # same second
    assert a != b
    assert a.exists() and b.exists()
