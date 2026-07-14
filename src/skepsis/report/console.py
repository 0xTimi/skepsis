"""Rich console rendering for interactive terminal use."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from skepsis.models import ScanReport, Severity, TriagedFinding

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(
    report: ScanReport, console: Console | None = None, *, show_rejected: bool = False
) -> None:
    console = console or Console()
    console.print(_summary(report))

    shown = report.results if show_rejected else report.confirmed
    shown = sorted(shown, key=lambda t: t.finding.severity.rank, reverse=True)
    if not shown:
        console.print("\n[green]No findings survived multi-model consensus.[/]")
        return

    console.print()
    for t in shown:
        console.print(_finding_panel(t))
        console.print()


def _summary(report: ScanReport) -> Table:
    table = Table(title=f"Skepsis audit — {report.target}", title_style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Rules run", str(report.rules_run))
    table.add_row("Candidates", str(len(report.results)))
    table.add_row("Confirmed", f"[bold]{len(report.confirmed)}[/]")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = len([t for t in report.confirmed if t.finding.severity is sev])
        if n:
            table.add_row(sev.value.title(), Text(str(n), style=_SEV_STYLE[sev]))
    return table


def _finding_panel(t: TriagedFinding) -> Panel:
    f = t.finding
    header = Text.assemble(
        (f" {f.severity.value.upper()} ", _SEV_STYLE[f.severity]),
        (f"  {f.title}  ", "bold"),
        (f"[{f.rule_id} · {f.cwe}]", "dim"),
    )
    body = Table.grid(padding=(0, 1))
    body.add_column(style="dim", justify="right")
    body.add_column()
    body.add_row("location", str(f.location))
    if f.tainted_symbol:
        body.add_row("tainted", f.tainted_symbol)
    if t.verdict:
        body.add_row("consensus", t.verdict.summary)
    if t.sanitizer:
        s = t.sanitizer
        status = "[green]reproduced[/]" if s.reproduced else f"{s.crashes}/{s.runs} crashed"
        body.add_row("sanitizer", status)

    code = _clean_snippet(f.snippet)
    syntax = Syntax(code, "c", theme="ansi_dark", line_numbers=False)

    group = Table.grid()
    group.add_row(body)
    group.add_row("")
    group.add_row(syntax)
    return Panel(group, title=header, border_style=_SEV_STYLE[f.severity].split()[-1])


def _clean_snippet(snippet: str) -> str:
    # Snippets carry a "> 1234 | code" gutter; strip it for syntax highlighting.
    out = []
    for line in snippet.splitlines():
        _, _, code = line.partition("| ")
        out.append(code)
    return "\n".join(out)
