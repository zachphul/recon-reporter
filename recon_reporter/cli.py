"""Recon Reporter CLI.

Examples:
  recon-reporter scan scanme.nmap.org --scope scope.yml --authorized
  recon-reporter scan 127.0.0.1 --scope scope.yml --authorized --no-ai
  recon-reporter scan demo --offline tests/fixtures/sample_nmap.xml --no-scope-check
"""
from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

# Windows legacy consoles default to cp1252; keep output UTF-8 safe.
try:  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
except Exception:
    pass

from . import __version__, logconf, pipeline, store
from . import dashboard as dashmod
from . import diff as diffmod
from .auth.scope import AuthorizationError, Scope
from .config import settings
from .report import csv as csvrep
from .report import html as htmlrep
from .report import markdown as md
from .report import pdf as pdfrep
from .report import sarif as sarifrep

app = typer.Typer(add_completion=False, help="AI-assisted reconnaissance reporting.")
console = Console()


def _execute_scan(
    *,
    target: str, scope: Path, authorized: bool, offline: Path | None,
    no_scope_check: bool, out: Path, profile: str, web: bool, http: bool,
    cve: bool, insecure: bool, no_ai: bool,
):
    """Shared core: authorize -> pipeline -> persist all report formats.
    Returns (ScanRun, Analysis|None, run_dir). Raises typer.Exit on gate/collect failure."""
    if offline and no_scope_check:
        console.print("[yellow]offline + --no-scope-check: skipping authorization gate[/yellow]")
    else:
        try:
            Scope.load(scope).require(target, acknowledged=authorized)
        except (AuthorizationError, FileNotFoundError) as e:
            console.print(f"[red]Authorization failed:[/red] {e}")
            raise typer.Exit(2) from None

    run_dir = store.make_run_dir(target, out)
    offline_xml = Path(offline).read_text(encoding="utf-8") if offline else None
    if offline:
        console.print(f"[dim]Loaded offline nmap XML: {offline}[/dim]")

    try:
        result = pipeline.run_pipeline(
            target, offline_xml=offline_xml, profile=profile, web=web, http=http,
            cve=cve, insecure=insecure, no_ai=no_ai, settings=settings,
            raw_sink=lambda tool, raw: store.save_raw(run_dir, tool, raw),
            progress=lambda m: console.print(f"[cyan]{m}[/cyan]"),
        )
    except pipeline.PipelineError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(3) from None

    run, analysis = result.scan, result.analysis
    store.save_findings(run_dir, run)
    store.save_report(run_dir, md.render(run, analysis))
    store.save_html(run_dir, htmlrep.render(run, analysis))
    store.save_sarif(run_dir, sarifrep.dumps(run, analysis))
    store.save_csv(run_dir, csvrep.to_csv(run, analysis))
    return run, analysis, run_dir


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
    pdf: bool = typer.Option(False, "--pdf", help="Also write a PDF (needs weasyprint; else prints how-to)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
    out: Path = typer.Option("runs", help="Output root directory."),
):
    """Run recon against TARGET and write a security report."""
    logconf.setup(verbose)
    console.print(f"[bold]Recon Reporter[/bold] v{__version__}")
    run, analysis, run_dir = _execute_scan(
        target=target, scope=scope, authorized=authorized, offline=offline,
        no_scope_check=no_scope_check, out=out, profile=profile, web=web, http=http,
        cve=cve, insecure=insecure, no_ai=no_ai,
    )
    if pdf:
        if pdfrep.to_pdf(htmlrep.render(run, analysis), run_dir / "report.pdf"):
            console.print(f"[green]PDF:[/green] {run_dir}\\report.pdf")
        else:
            console.print("[yellow]PDF skipped — `pip install weasyprint`, or print "
                          "report.html from a browser.[/yellow]")
    n_services = sum(len(h.services) for h in run.hosts)
    console.print(f"Parsed [bold]{len(run.hosts)}[/bold] host(s), "
                  f"[bold]{n_services}[/bold] open service(s), "
                  f"[bold]{len(run.flags)}[/bold] finding(s).")
    if analysis:
        ungrounded = sum(1 for f in analysis.findings if not f.grounded)
        console.print(f"AI produced [bold]{len(analysis.findings)}[/bold] finding(s)"
                      + (f" ([yellow]{ungrounded} ungrounded[/yellow])" if ungrounded else ""))
    console.print(f"\n[green]Reports:[/green] {run_dir}\\report.md · report.html · report.sarif.json")


@app.command()
def monitor(
    target: str = typer.Argument(..., help="Host/IP to monitor (must be in scope)."),
    scope: Path = typer.Option("scope.yml", help="Authorization scope file."),
    authorized: bool = typer.Option(False, "--authorized", help="Assert you are permitted to test this target."),
    profile: str = typer.Option("default", help="nmap profile."),
    offline: Path = typer.Option(None, help="Use an existing nmap XML (testing)."),
    no_scope_check: bool = typer.Option(False, "--no-scope-check", help="Skip scope gate (only with --offline)."),
    fail_on_new: bool = typer.Option(False, "--fail-on-new", help="Exit 1 if new findings appeared (for CI/alerts)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
    out: Path = typer.Option("runs", help="Output root directory."),
):
    """Scan TARGET and diff it against its most recent prior run (drift monitoring)."""
    logconf.setup(verbose)
    console.print(f"[bold]Recon Reporter[/bold] v{__version__} — monitor")
    prior = store.latest_findings(target, out)  # capture BEFORE the new run is created
    run, _analysis, run_dir = _execute_scan(
        target=target, scope=scope, authorized=authorized, offline=offline,
        no_scope_check=no_scope_check, out=out, profile=profile,
        web=False, http=False, cve=False, insecure=False, no_ai=True,
    )
    if prior is None:
        console.print("[yellow]No prior run for this target — baseline established.[/yellow]")
        return
    d = diffmod.diff_runs(diffmod.load_run(prior), run)
    (run_dir / "diff.md").write_text(diffmod.render_markdown(d), encoding="utf-8")
    changed = bool(d["opened"] or d["closed"] or d["changed"] or d["new_flags"])
    console.print(f"Diff vs prior: [bold]{len(d['opened'])}[/bold] opened · "
                  f"[bold]{len(d['closed'])}[/bold] closed · "
                  f"[bold]{len(d['new_flags'])}[/bold] new flag(s)  [dim]({run_dir}\\diff.md)[/dim]")
    if changed:
        console.print("[bold yellow]Changes detected since last run.[/bold yellow]")
    if changed and fail_on_new:
        raise typer.Exit(1)


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
def dashboard(
    runs: Path = typer.Option("runs", help="Runs directory to aggregate."),
    out: Path = typer.Option(None, help="Output HTML (default: <runs>/dashboard.html)."),
):
    """Build an HTML dashboard aggregating every run under the runs directory."""
    target = out or (Path(runs) / "dashboard.html")
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    Path(target).write_text(dashmod.build_dashboard(runs), encoding="utf-8")
    console.print(f"[green]Dashboard:[/green] {target}")


@app.command()
def version():
    """Print version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
