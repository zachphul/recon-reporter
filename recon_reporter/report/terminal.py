"""A rich terminal table of findings, printed at the end of a scan so the operator sees
the headline results without opening a file."""
from __future__ import annotations

from rich.table import Table

from ..model import ScanRun, Severity

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "dim",
}


def findings_table(run: ScanRun) -> Table:
    t = Table(title=f"Findings — {run.target}", title_style="bold", show_lines=False,
              header_style="bold")
    t.add_column("Severity", no_wrap=True)
    t.add_column("Finding")
    t.add_column("Where", no_wrap=True, style="cyan")
    for f in sorted(run.flags, key=lambda f: f.severity.rank, reverse=True):
        loc = f"{f.host}:{f.port}" if f.port else f.host
        t.add_row(f"[{_STYLE[f.severity]}]{f.severity.value.upper()}[/]", f.title, loc)
    if not run.flags:
        t.add_row("[dim]—[/]", "[dim]no rule findings[/]", "")
    return t
