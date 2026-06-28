"""CLI integration tests via Typer's runner — scan, dashboard, monitor. No network."""
from pathlib import Path

from typer.testing import CliRunner

from recon_reporter.cli import app

runner = CliRunner()
FIXTURE = str(Path(__file__).parent / "fixtures" / "sample_nmap.xml")

# Minimal nmap XML pairs for the monitor diff (telnet appears in B).
_XML_A = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>"""

_XML_B = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
</ports></host></nmaprun>"""


def test_scan_offline_cli(tmp_path):
    res = runner.invoke(app, ["scan", "demo", "--offline", FIXTURE,
                              "--no-scope-check", "--no-ai", "--out", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert list(tmp_path.glob("*/report.md"))
    assert list(tmp_path.glob("*/report.sarif.json"))


def test_scope_gate_blocks_via_cli(tmp_path):
    scope = tmp_path / "scope.yml"
    scope.write_text("authorized_targets:\n  - 127.0.0.1\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", "8.8.8.8", "--scope", str(scope), "--authorized",
                              "--out", str(tmp_path)])
    assert res.exit_code == 2


def test_dashboard_cli(tmp_path):
    runner.invoke(app, ["scan", "demo", "--offline", FIXTURE, "--no-scope-check",
                        "--no-ai", "--out", str(tmp_path)])
    out = tmp_path / "dashboard.html"
    res = runner.invoke(app, ["dashboard", "--runs", str(tmp_path), "--out", str(out)])
    assert res.exit_code == 0
    assert out.exists() and "Dashboard" in out.read_text(encoding="utf-8")


def test_monitor_baseline_then_detects_change(tmp_path):
    a = tmp_path / "a.xml"
    a.write_text(_XML_A, encoding="utf-8")
    b = tmp_path / "b.xml"
    b.write_text(_XML_B, encoding="utf-8")
    r1 = runner.invoke(app, ["monitor", "host", "--offline", str(a),
                             "--no-scope-check", "--out", str(tmp_path)])
    assert r1.exit_code == 0
    assert "baseline" in r1.output.lower()
    r2 = runner.invoke(app, ["monitor", "host", "--offline", str(b), "--no-scope-check",
                             "--fail-on-new", "--out", str(tmp_path)])
    assert r2.exit_code == 1  # telnet appeared -> new finding -> fail-on-new
    assert list(tmp_path.glob("*/diff.md"))
