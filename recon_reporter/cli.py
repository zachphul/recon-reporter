"""Recon Reporter CLI.

Examples:
  recon-reporter scan scanme.nmap.org --scope scope.yml --authorized
  recon-reporter scan 127.0.0.1 --scope scope.yml --authorized --no-ai
  recon-reporter scan demo --offline tests/fixtures/sample_nmap.xml --no-scope-check
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console

# Windows legacy consoles default to cp1252; keep output UTF-8 safe.
try:  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
except Exception:
    pass

from . import __version__, logconf, store
from . import diff as diffmod
from .ai.analyst import get_analyst
from .auth.scope import AuthorizationError, Scope
from .collectors import tls as tlsmod
from .collectors import whatweb as whatwebmod
from .collectors.http_headers import HttpHeaderCollector
from .collectors.nmap import NmapCollector
from .config import settings
from .enrich import rules
from .enrich.cve import CveLookup
from .model import ScanRun
from .parsers.nmap_xml import parse_nmap_xml
from .report import html as htmlrep
from .report import markdown as md
from .report import sarif as sarifrep

app = typer.Typer(add_completion=False, help="AI-assisted reconnaissance reporting.")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Host/IP to assess (must be in scope)."),
    scope: Path = typer.Option("scope.yml", help="Authorization scope file."),
    authorized: bool = typer.Option(False, "--authorized", help="Assert you are permitted to test this target."),
    profile: str = typer.Option("default", help="nmap profile: default | quick | full."),
    offline: Path = typer.Option(None, help="Use an existing nmap XML file instead of scanning."),
    no_scope_check: bool = typer.Option(False, "--no-scope-check", help="Skip scope gate (only valid with --offline)."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip the LLM analysis (rule findings only)."),
    cve: bool = typer.Option(False, "--cve", help="Enrich services with NVD CVE matches (needs network)."),
    web: bool = typer.Option(False, "--web", help="Also run whatweb + sslscan (web/TLS recon)."),
    http: bool = typer.Option(False, "--http", help="Grade HTTP security headers (pure Python; needs network)."),
    insecure: bool = typer.Option(False, "--insecure", help="Skip TLS cert verification for --http (reach bad-cert hosts)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
    out: Path = typer.Option("runs", help="Output root directory."),
):
    """Run recon against TARGET and write a security report."""
    logconf.setup(verbose)
    console.print(f"[bold]Recon Reporter[/bold] v{__version__}")

    # 1) Authorization gate
    if offline and no_scope_check:
        console.print("[yellow]offline + --no-scope-check: skipping authorization gate[/yellow]")
    else:
        try:
            Scope.load(scope).require(target, acknowledged=authorized)
        except (AuthorizationError, FileNotFoundError) as e:
            console.print(f"[red]Authorization failed:[/red] {e}")
            raise typer.Exit(2) from None

    started = datetime.now()
    run = ScanRun(target=target, started_at=started)
    run_dir = store.make_run_dir(target, out)

    # 2) Collect
    if offline:
        xml = Path(offline).read_text(encoding="utf-8")
        console.print(f"[dim]Loaded offline nmap XML: {offline}[/dim]")
        run.tool_versions["nmap"] = "offline"
    else:
        nm = NmapCollector(profile=profile)
        if not nm.available():
            console.print("[red]nmap not found on PATH. Install it (Kali ships with it) or use --offline.[/red]")
            raise typer.Exit(3)
        console.print(f"[cyan]Running nmap ({profile})…[/cyan] this can take a few minutes")
        res = nm.run(target)
        if not res.ok:
            console.print(f"[red]nmap failed:[/red] {res.error}")
            raise typer.Exit(3)
        xml = res.raw
        run.tool_versions["nmap"] = res.version or "unknown"
    store.save_raw(run_dir, "nmap", xml)

    # 3) Parse
    run.hosts = parse_nmap_xml(xml)
    n_services = sum(len(h.services) for h in run.hosts)

    # 3b) Extra web/TLS collectors (merge into the model before rules run)
    if web and not offline:
        for coll, merge, label in (
            (whatwebmod.WhatWebCollector(), whatwebmod.merge_into_hosts, "whatweb"),
            (tlsmod.TlsCollector(), tlsmod.merge_into_hosts, "sslscan"),
        ):
            if coll.available():
                console.print(f"[cyan]Running {label}…[/cyan]")
                r = coll.run(target)
                if r.ok:
                    store.save_raw(run_dir, label, r.raw)
                    merge(r.raw, run.hosts)
                    run.tool_versions[label] = "present"
                else:
                    console.print(f"[yellow]{label}: {r.error}[/yellow]")
            else:
                console.print(f"[dim]{label} not installed — skipping[/dim]")

    # 3b2) HTTP security-header grading (pure Python; produces flags directly)
    header_flags = []
    if http and not offline:
        console.print("[cyan]Grading HTTP security headers…[/cyan]")
        header_flags = HttpHeaderCollector(verify=not insecure).collect(run.hosts)
        console.print(f"  {len(header_flags)} header finding(s).")

    # 3c) CVE enrichment
    if cve:
        console.print("[cyan]Querying NVD for CVEs…[/cyan] (rate-limited; cached)")
        added = CveLookup(api_key=settings.nvd_api_key).enrich(run.hosts)
        console.print(f"Attached [bold]{added}[/bold] CVE reference(s).")

    # 4) Deterministic rule enrichment (after all collectors have contributed)
    run.flags = rules.evaluate(run.hosts) + header_flags
    console.print(f"Parsed [bold]{len(run.hosts)}[/bold] host(s), "
                  f"[bold]{n_services}[/bold] open service(s), "
                  f"[bold]{len(run.flags)}[/bold] rule flag(s).")

    # 5) AI analysis
    analysis = None
    if not no_ai:
        provider = settings.resolved_provider()
        console.print(f"[cyan]Analyzing with provider: {provider}[/cyan]")
        try:
            analysis = get_analyst().analyze(run)
            ungrounded = sum(1 for f in analysis.findings if not f.grounded)
            console.print(f"AI produced [bold]{len(analysis.findings)}[/bold] finding(s)"
                          + (f" ([yellow]{ungrounded} ungrounded[/yellow])" if ungrounded else ""))
        except Exception as e:
            console.print(f"[yellow]AI analysis skipped ({type(e).__name__}: {e}). "
                          f"Writing rule-based report.[/yellow]")

    # 6) Persist (markdown + HTML + structured JSON)
    run.finished_at = datetime.now()
    store.save_findings(run_dir, run)
    report_path = store.save_report(run_dir, md.render(run, analysis))
    html_path = store.save_html(run_dir, htmlrep.render(run, analysis))
    sarif_path = store.save_sarif(run_dir, sarifrep.dumps(run, analysis))

    console.print(f"\n[green]Report written:[/green] {report_path}")
    console.print(f"[green]HTML report:[/green]    {html_path}")
    console.print(f"[green]SARIF:[/green]          {sarif_path}")
    console.print(f"[dim]  Raw + findings.json in {run_dir}[/dim]")


@app.command()
def diff(
    old: Path = typer.Argument(..., help="Older findings.json"),
    new: Path = typer.Argument(..., help="Newer findings.json"),
    out: Path = typer.Option(None, help="Write the diff markdown here (else print)."),
):
    """Compare two saved runs and report what changed (drift over time)."""
    d = diffmod.diff_runs(diffmod.load_run(old), diffmod.load_run(new))
    report = diffmod.render_markdown(d)
    if out:
        Path(out).write_text(report, encoding="utf-8")
        console.print(f"[green]Diff written:[/green] {out}")
    else:
        console.print(report)


@app.command()
def version():
    """Print version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
