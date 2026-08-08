"""`logarc` command line entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from logarc import __version__
from logarc.case import Case, CaseError
from logarc.ingest.pipeline import FormatDetectionError
from logarc.ingest.reader import LogSourceError
from logarc.parsers.apache import PRESETS
from logarc.parsers.registry import UnknownFormatError
from logarc.storage.event_store import SORT_KEYS

app = typer.Typer(
    name="logarc",
    help="Reconstruct what an IP did on a web server, from its access logs.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
errors = Console(stderr=True)

#: Errors that represent a bad request from the user rather than a defect. These
#: are reported as a single line; anything else keeps its traceback, because an
#: unexpected failure in a forensic tool should be loud.
USER_ERRORS = (CaseError, FormatDetectionError, LogSourceError, UnknownFormatError, ValueError)


def _fail(message: str) -> typer.Exit:
    errors.print(f"[red]error:[/red] {message}")
    return typer.Exit(code=1)


def _version_callback(requested: bool) -> None:
    if requested:
        console.print(f"logarc {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Reconstruct what an IP did on a web server, from its access logs."""


@app.command()
def ingest(
    logs: Annotated[list[Path], typer.Argument(help="Log files to read.")],
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to create.")],
    log_format: Annotated[
        str | None,
        typer.Option("--format", "-f", help="Log format name. Detected automatically if omitted."),
    ] = None,
) -> None:
    """Read logs into a new case."""
    try:
        with Case.create(case) as opened:
            results = opened.ingest(logs, log_format=log_format)
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    table = Table(title=f"Ingested into {case}")
    for column in ("Source", "Format", "Lines", "Events", "Quarantined", "Lines/s"):
        table.add_column(column, justify="right" if column != "Source" else "left")
    for result in results:
        table.add_row(
            result.file_id,
            result.log_format,
            f"{result.lines_read:,}",
            f"{result.events_parsed:,}",
            f"{result.lines_quarantined:,}",
            f"{result.lines_per_second:,.0f}",
        )
    console.print(table)

    quarantined = sum(result.lines_quarantined for result in results)
    if quarantined:
        console.print(
            f"[yellow]{quarantined:,} line(s) could not be parsed[/yellow] — "
            f"see {case / 'quarantine' / 'unparsed.jsonl'}"
        )


@app.command("list-ips")
def list_ips(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    limit: Annotated[int, typer.Option("--limit", "-n", help="How many to show.")] = 20,
    sort: Annotated[
        str, typer.Option("--sort", "-s", help=f"One of: {', '.join(SORT_KEYS)}.")
    ] = "requests",
) -> None:
    """List the clients seen in a case."""
    try:
        with Case.open(case) as opened:
            summaries = opened.store.ip_summaries(limit=limit, order_by=sort)
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if not summaries:
        console.print("[yellow]No events in this case.[/yellow]")
        return

    table = Table(title=f"Clients in {case}")
    table.add_column("IP")
    for column in ("Requests", "Paths", "4xx", "Bytes"):
        table.add_column(column, justify="right")
    table.add_column("First seen")
    table.add_column("Last seen")
    for summary in summaries:
        table.add_row(
            summary.client_ip,
            f"{summary.request_count:,}",
            f"{summary.distinct_paths:,}",
            f"{summary.client_error_ratio:.0%}",
            f"{summary.bytes_total:,}",
            summary.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            summary.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        )
    console.print(table)


@app.command()
def formats() -> None:
    """List the log formats that can be parsed."""
    table = Table(title="Known log formats")
    table.add_column("Name")
    table.add_column("LogFormat directive")
    for name, directive in PRESETS.items():
        table.add_row(name, directive)
    console.print(table)
    console.print(
        "\nA custom Apache or nginx format is supported by passing its directive "
        "string; there is no need for it to be listed here."
    )
