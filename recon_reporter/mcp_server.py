"""MCP server wrapper — exposes Recon Reporter as tools an AI agent can call over the
Model Context Protocol. Ties the project to your MCP certification.

Run:  python -m recon_reporter.mcp_server     (requires `pip install mcp`)

Tools exposed:
  - recon_scan(target, scope_file, authorized): run a scan, return structured findings
  - recon_rules(target, scope_file, authorized): findings without the LLM layer

The scope gate still applies — the agent cannot scan anything not in the scope file.
"""
from __future__ import annotations

from datetime import datetime

from .auth.scope import AuthorizationError, Scope
from .collectors.nmap import NmapCollector
from .enrich import rules
from .model import ScanRun
from .parsers.nmap_xml import parse_nmap_xml

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None  # type: ignore


def _run_scan(target: str, scope_file: str, authorized: bool, profile: str = "default") -> ScanRun:
    Scope.load(scope_file).require(target, acknowledged=authorized)
    nm = NmapCollector(profile=profile)
    if not nm.available():
        raise RuntimeError("nmap not installed on this host")
    res = nm.run(target)
    if not res.ok:
        raise RuntimeError(f"nmap failed: {res.error}")
    run = ScanRun(target=target, started_at=datetime.now(),
                  tool_versions={"nmap": res.version or "unknown"})
    run.hosts = parse_nmap_xml(res.raw)
    run.flags = rules.evaluate(run.hosts)
    run.finished_at = datetime.now()
    return run


def build_server():  # pragma: no cover - requires mcp + network
    if FastMCP is None:
        raise SystemExit("MCP not installed. Run: pip install mcp")
    mcp = FastMCP("recon-reporter")

    @mcp.tool()
    def recon_rules(target: str, scope_file: str = "scope.yml", authorized: bool = False) -> dict:
        """Run recon on an in-scope target and return structured findings (no LLM)."""
        try:
            run = _run_scan(target, scope_file, authorized)
        except AuthorizationError as e:
            return {"error": "authorization", "detail": str(e)}
        except Exception as e:
            return {"error": type(e).__name__, "detail": str(e)}
        return run.model_dump(mode="json")

    return mcp


if __name__ == "__main__":  # pragma: no cover
    build_server().run()
