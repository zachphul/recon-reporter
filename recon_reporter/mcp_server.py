"""MCP server wrapper — exposes ReconLens as tools an AI agent can call over the
Model Context Protocol. Ties the project to your MCP certification.

Run:  python -m recon_reporter.mcp_server     (requires `pip install mcp`)

Tools exposed:
  - recon_scan(target, scope_file, authorized): run a scan with AI analysis
  - recon_rules(target, scope_file, authorized): findings without the LLM layer

The scope gate still applies — the agent cannot scan anything not in the scope file.
"""
from __future__ import annotations

from .ai.base import Analysis
from .auth.scope import AuthorizationError, Scope
from .config import settings
from .model import ScanRun
from .pipeline import run_pipeline

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None  # type: ignore


def _run_scan(target: str, scope_file: str, authorized: bool, profile: str = "default",
              no_ai: bool = False) -> tuple[ScanRun, Analysis | None]:
    Scope.load(scope_file).require(target, acknowledged=authorized)
    result = run_pipeline(
        target, profile=profile, no_ai=no_ai, settings=settings,
        progress=lambda m: None,
    )
    return result.scan, result.analysis


def build_server():  # pragma: no cover - requires mcp + network
    if FastMCP is None:
        raise SystemExit("MCP not installed. Run: pip install mcp")
    mcp = FastMCP("reconlens")

    @mcp.tool()
    def recon_scan(target: str, scope_file: str = "scope.yml", authorized: bool = False) -> dict:
        """Run a full recon scan on an in-scope target with AI analysis and return findings."""
        try:
            run, analysis = _run_scan(target, scope_file, authorized, no_ai=False)
        except AuthorizationError as e:
            return {"error": "authorization", "detail": str(e)}
        except Exception as e:
            return {"error": type(e).__name__, "detail": str(e)}
        result = run.model_dump(mode="json")
        if analysis:
            result["analysis"] = analysis.model_dump(mode="json")
        return result

    @mcp.tool()
    def recon_rules(target: str, scope_file: str = "scope.yml", authorized: bool = False) -> dict:
        """Run recon on an in-scope target and return rule-based findings (no LLM)."""
        try:
            run, _analysis = _run_scan(target, scope_file, authorized, no_ai=True)
        except AuthorizationError as e:
            return {"error": "authorization", "detail": str(e)}
        except Exception as e:
            return {"error": type(e).__name__, "detail": str(e)}
        return run.model_dump(mode="json")

    return mcp


if __name__ == "__main__":  # pragma: no cover
    build_server().run()
