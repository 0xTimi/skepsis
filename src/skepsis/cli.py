"""Command-line interface.

skepsis scan   PATH          # full pipeline: scan → consensus
skepsis verify HARNESS.c     # dynamic sanitizer verification
skepsis rules                # list detection rules
skepsis version
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from skepsis import __version__
from skepsis.config import Settings
from skepsis.consensus.providers import ProviderError
from skepsis.models import Severity, TriagedFinding
from skepsis.orchestrator import Skepsis
from skepsis.report import render_console, to_markdown, to_sarif_json
from skepsis.scanner.patterns import RULES
from skepsis.verify.sanitizer import SanitizerRunner

app = typer.Typer(
    name="skepsis",
    help="Multi-model consensus + sanitizer verification for C/C++ memory bugs.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"skepsis {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    _version: bool | None = typer.Option(
        None, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """Skepsis — hunt memory-safety bugs with a panel of models as your jury."""


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, help="File or directory to audit."),
    panel: str | None = typer.Option(
        None, "--panel", "-p", help="Comma-separated provider ids, e.g. 'anthropic,openai,mock'."
    ),
    fmt: str = typer.Option("console", "--format", "-f", help="console | markdown | sarif."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write report to a file."),
    min_severity: Severity = typer.Option(
        Severity.LOW, "--min-severity", "-s", help="Drop findings below this severity."
    ),
    threshold: float | None = typer.Option(
        None, "--threshold", "-t", min=0.0, max=1.0, help="Consensus confirmation threshold."
    ),
    no_triage: bool = typer.Option(
        False, "--no-triage", help="Skip the consensus panel (raw candidates only)."
    ),
    show_rejected: bool = typer.Option(
        False, "--show-rejected", help="Include findings the panel rejected."
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", "-x", help="Glob(s) of paths to skip, e.g. '*/test*' (repeatable)."
    ),
) -> None:
    """Scan PATH and triage findings through the multi-model consensus panel."""
    settings = _settings(panel=panel, threshold=threshold)
    if exclude:
        settings.exclude = list(exclude)
    try:
        engine = Skepsis(settings)
        if not no_triage:
            engine.make_panel()  # fail fast on bad provider/credentials
    except ProviderError as exc:
        err.print(f"[red]Provider error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=None)

        def hook(i: int, total: int, triaged: TriagedFinding) -> None:
            progress.update(task, description=f"Triaging {i}/{total}: {triaged.finding.rule_id}")

        report = engine.audit(path, triage=not no_triage, progress=hook)

    # Severity filtering (post-triage so counts stay meaningful upstream).
    report.results = [r for r in report.results if r.finding.severity.rank >= min_severity.rank]

    rendered = _render(report, fmt, show_rejected=show_rejected)
    if out and rendered is not None:
        out.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote {fmt} report to[/] {out}")
    elif out:
        err.print("[yellow]The 'console' format can't be written to a file; use markdown/sarif.[/]")
    elif rendered is not None:
        # Machine-readable formats go to raw stdout — never through Rich, whose
        # markup parsing and soft-wrapping would corrupt JSON/Markdown payloads.
        typer.echo(rendered)

    # Exit non-zero when confirmed findings exist (handy in CI).
    raise typer.Exit(code=1 if report.confirmed else 0)


@app.command()
def verify(
    harness: Path = typer.Argument(..., exists=True, help="Self-contained C proof-of-concept."),
    runs: int = typer.Option(20, "--runs", "-n", min=1, help="Number of executions."),
    sanitizers: str = typer.Option("address,undefined", "--sanitizers", help="-fsanitize= list."),
    cc: str = typer.Option("cc", "--cc", help="C compiler to use."),
) -> None:
    """Compile HARNESS with sanitizers and run it repeatedly, reporting crash rate."""
    runner = SanitizerRunner(cc, sanitizers=sanitizers)
    if not runner.available():
        err.print(f"[red]C compiler {cc!r} not found on PATH.[/]")
        raise typer.Exit(code=2)
    try:
        result = runner.verify_file(harness.name, harness, runs=runs)
    except RuntimeError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc

    verdict = "[green]REPRODUCED[/]" if result.reproduced else "[yellow]not reproduced[/]"
    console.print(
        f"{verdict}  crash rate {result.crash_rate:.0%} "
        f"({result.crashes}/{result.runs} runs, sanitizer={result.sanitizer})"
    )
    if result.first_error:
        console.print(f"[dim]{result.first_error}[/]")
    raise typer.Exit(code=0 if result.reproduced else 1)


@app.command()
def rules() -> None:
    """List the built-in detection rules."""
    table = Table(title="Skepsis detection rules")
    table.add_column("ID", style="bold")
    table.add_column("Class")
    table.add_column("Severity")
    table.add_column("CWE")
    table.add_column("Title")
    for rule in RULES:
        table.add_row(
            rule.id, rule.vuln_class.value, rule.severity.value, rule.vuln_class.cwe, rule.title
        )
    console.print(table)


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"skepsis {__version__}")


# -- helpers --------------------------------------------------------------


def _settings(*, panel: str | None, threshold: float | None) -> Settings:
    settings = Settings()
    if panel:
        settings.panel = [p.strip() for p in panel.split(",") if p.strip()]
    if threshold is not None:
        settings.confirm_threshold = threshold
    return settings


def _render(report, fmt: str, *, show_rejected: bool) -> str | None:  # type: ignore[no-untyped-def]
    fmt = fmt.lower()
    if fmt == "console":
        render_console(report, console, show_rejected=show_rejected)
        return None
    if fmt in {"md", "markdown"}:
        return to_markdown(report)
    if fmt == "sarif":
        return to_sarif_json(report, include_rejected=show_rejected)
    err.print(f"[red]Unknown format {fmt!r}. Use console | markdown | sarif.[/]")
    raise typer.Exit(code=2)


if __name__ == "__main__":  # pragma: no cover
    app()
