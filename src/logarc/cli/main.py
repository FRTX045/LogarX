"""`logarc` command line entry point."""

from __future__ import annotations

import json
import platform
import shutil
import tempfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Final

import typer
from rich.console import Console
from rich.table import Table

from logarc import __version__
from logarc.analysis import AnalysisPolicy, analyse_ip
from logarc.case import Case, CaseError
from logarc.core.activity import Severity
from logarc.detect.rules import RulePackError
from logarc.episode.builder import EpisodePolicy
from logarc.evaluation.benchmark import BenchmarkError, BenchmarkResult, run_benchmark
from logarc.evaluation.generator import DEFAULT_SEED, describe_scenarios, write_log
from logarc.evaluation.scoring import evaluate as score_case
from logarc.evaluation.truth import TruthError, read_truth
from logarc.ingest.pipeline import FormatDetectionError
from logarc.ingest.reader import LogSourceError
from logarc.parsers.apache import PRESETS
from logarc.parsers.registry import UnknownFormatError
from logarc.report.html import render_report
from logarc.sessionize.segmenter import SessionPolicy
from logarc.storage.event_store import SORT_KEYS

#: Sizes the benchmark measures when none are named. Ten million is deliberately
#: not here: it takes minutes, and a default should not.
DEFAULT_BENCHMARK_SIZES: Final = (100_000, 1_000_000)

_SEVERITY_STYLE: Final[dict[Severity, str]] = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bright_red",
    Severity.CRITICAL: "bold red",
}

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
USER_ERRORS = (
    CaseError,
    FormatDetectionError,
    LogSourceError,
    RulePackError,
    TruthError,
    UnknownFormatError,
    ValueError,
)


def _fail(message: str) -> typer.Exit:
    errors.print(f"[red]error:[/red] {message}")
    return typer.Exit(code=1)


def _analysis_policy(
    *, absorb: bool, episode_gap: int | None, idle_timeout: int | None
) -> AnalysisPolicy:
    """Build a policy from the thresholds a user chose to override."""
    session = SessionPolicy()
    if idle_timeout is not None:
        session = replace(session, idle_timeout=timedelta(seconds=idle_timeout))

    episode = EpisodePolicy(absorb_noise=absorb)
    if episode_gap is not None:
        episode = replace(episode, max_gap=timedelta(seconds=episode_gap))

    return AnalysisPolicy(session=session, episode=episode)


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
def analyze(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    ip: Annotated[str, typer.Option("--ip", help="Client address to reconstruct.")],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the graph as JSON to this path.")
    ] = None,
) -> None:
    """Reconstruct one client's activity as a graph."""
    try:
        with Case.open(case) as opened:
            result = analyse_ip(opened.store, ip)
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if not result.episodes:
        console.print(f"[yellow]No activity found for {ip} in this case.[/yellow]")
        return

    table = Table(title=f"Activity of {ip}")
    table.add_column("Time")
    table.add_column("Activity")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Requests", justify="right")
    table.add_column("Outcome")
    for episode in result.episodes:
        table.add_row(
            episode.start.strftime("%Y-%m-%d %H:%M:%S"),
            episode.label,
            f"[{_SEVERITY_STYLE[episode.severity]}]{episode.severity.name.title()}[/]",
            episode.activity.owasp or "-",
            f"{episode.request_count:,}",
            episode.outcome.value,
        )
    console.print(table)
    console.print(
        f"{result.request_count:,} requests across {len(result.sessions)} session(s) "
        f"reduced to {len(result.episodes)} activities."
    )

    if out is not None:
        out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"Graph written to {out}")


@app.command()
def export(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    ip: Annotated[str, typer.Option("--ip", help="Client address to report on.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="File to write.")],
    output_format: Annotated[str, typer.Option("--format", "-f", help="html or json.")] = "html",
) -> None:
    """Write a standalone report for one client."""
    if output_format not in {"html", "json"}:
        raise _fail(f"unknown format {output_format!r}; choose html or json")

    try:
        with Case.open(case) as opened:
            result = analyse_ip(opened.store, ip)
            manifest = opened.manifest
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if output_format == "json":
        out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    else:
        out.write_text(render_report(result, manifest), encoding="utf-8")
    console.print(f"Report written to {out}")


@app.command()
def generate(
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Log file to write.")] = None,
    scenario: Annotated[
        str, typer.Option("--scenario", "-s", help="Which traffic to generate.")
    ] = "mixed",
    lines: Annotated[int, typer.Option("--lines", "-n", help="How many lines.")] = 100_000,
    seed: Annotated[int, typer.Option("--seed", help="Same seed, same log.")] = DEFAULT_SEED,
    truth: Annotated[
        Path | None,
        typer.Option("--truth", "-t", help="Write the ground truth here, for evaluate."),
    ] = None,
    list_scenarios: Annotated[
        bool, typer.Option("--list", "-l", help="List the scenarios and stop.")
    ] = False,
) -> None:
    """Write a synthetic access log with a known answer."""
    if list_scenarios:
        table = Table(title="Scenarios")
        table.add_column("Name")
        table.add_column("Contains")
        for name, description in describe_scenarios():
            table.add_row(name, description)
        console.print(table)
        return

    if out is None:
        raise _fail("--out is required unless --list is given")

    with console.status(f"Generating {lines:,} lines…") as status:
        try:
            result = write_log(
                out,
                scenario=scenario,
                lines=lines,
                seed=seed,
                truth_path=truth,
                on_progress=lambda done: status.update(f"Generated {done:,} of {lines:,} lines…"),
            )
        except USER_ERRORS as exc:
            raise _fail(str(exc)) from exc

    console.print(
        f"Wrote {result.lines:,} lines ({result.megabytes:,.1f} MB) of "
        f"[bold]{result.scenario}[/bold] to {result.path} "
        f"in {result.elapsed_seconds:.1f}s (seed {result.seed})"
    )
    if result.truth_path is not None:
        console.print(f"Ground truth written to {result.truth_path}")


@app.command()
def evaluate(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    truth: Annotated[Path, typer.Option("--truth", "-t", help="Ground truth for its log.")],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the full numbers as JSON.")
    ] = None,
    absorb: Annotated[
        bool,
        typer.Option(
            "--absorb/--no-absorb",
            help="Merge activities split only by a brief benign interlude.",
        ),
    ] = True,
    episode_gap: Annotated[
        int | None, typer.Option("--episode-gap", help="Seconds of silence that end an activity.")
    ] = None,
    idle_timeout: Annotated[
        int | None, typer.Option("--idle-timeout", help="Seconds of silence that end a session.")
    ] = None,
) -> None:
    """Measure the reconstruction against a log whose content is known.

    The thresholds can be overridden so their effect can be measured rather
    than assumed; `--no-absorb` turns off noise absorption, which is the one
    rule in the segmentation whose cost is worth showing both ways.
    """
    policy = _analysis_policy(absorb=absorb, episode_gap=episode_gap, idle_timeout=idle_timeout)
    try:
        loaded = read_truth(truth)
        with Case.open(case) as opened, console.status("Scoring…") as status:
            report = score_case(
                opened.store,
                loaded,
                policy=policy,
                on_client=lambda client: status.update(f"Scoring {client}…"),
            )
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if not report.classification.total:
        console.print("[yellow]Nothing to score: no truth line matched a stored event.[/yellow]")
        return

    table = Table(title=f"Classification — {report.scenario}")
    table.add_column("Activity")
    for column in ("Support", "Predicted", "Precision", "Recall", "F1", "Recall(any)"):
        table.add_column(column, justify="right")
    for score in report.classification.scores:
        table.add_row(
            score.category.value,
            f"{score.support:,}",
            f"{score.predicted:,}",
            f"{score.precision:.3f}",
            f"{score.recall:.3f}",
            f"{score.f1:.3f}",
            f"{score.recall_any:.3f}",
        )
    console.print(table)
    console.print(
        f"accuracy {report.classification.accuracy:.3f}   "
        f"macro F1 {report.classification.macro_f1:.3f}   "
        f"weighted F1 {report.classification.weighted_f1:.3f}   "
        f"({report.clients:,} clients, {report.lines_scored:,} requests, "
        f"{report.lines_missing:,} unmatched)"
    )

    confusions = report.classification.top_confusions(limit=5)
    if confusions:
        console.print("\n[bold]Most frequent mistakes[/bold]")
        for expected, predicted, count in confusions:
            console.print(f"  {expected.value} read as {predicted.value}: {count:,}")

    segmentation = report.segmentation
    console.print(
        f"\n[bold]Boundaries[/bold] precision {segmentation.boundary_precision:.3f}   "
        f"recall {segmentation.boundary_recall:.3f}   F1 {segmentation.boundary_f1:.3f}\n"
        f"{segmentation.truth_activities:,} activities in the log became "
        f"{segmentation.predicted_episodes:,} episodes "
        f"(x{segmentation.fragmentation:.2f}); below 1.0 is deliberate coarsening."
    )

    if out is not None:
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"\nFull numbers written to {out}")


@app.command()
def benchmark(
    lines: Annotated[
        list[int] | None,
        typer.Option("--lines", "-n", help="Corpus size to measure. Repeatable."),
    ] = None,
    scenario: Annotated[str, typer.Option("--scenario", "-s", help="Traffic to measure on.")] = (
        "mixed"
    ),
    seed: Annotated[int, typer.Option("--seed", help="Same seed, same corpus.")] = 1,
    work: Annotated[
        Path | None, typer.Option("--work", help="Where to put the working files.")
    ] = None,
    keep: Annotated[bool, typer.Option("--keep", help="Do not delete the working files.")] = False,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the measurements as JSON.")
    ] = None,
) -> None:
    """Measure ingest throughput, peak memory and reconstruction time.

    Each size runs in a process of its own: peak memory is a high-water mark
    for the life of a process, so measuring several sizes in one would report
    the largest run's peak for every run after it.
    """
    sizes = lines or list(DEFAULT_BENCHMARK_SIZES)

    # Always work inside a directory of our own making, even when the user
    # named where to put it. Cleanup then removes only what this run created,
    # so pointing --work at somewhere that already has files in it is safe.
    root = Path(work) if work is not None else Path(tempfile.gettempdir())
    root.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="logarc-bench-", dir=root))

    table = Table(title=f"Ingest — {scenario}")
    table.add_column("Lines", justify="right")
    for column in ("MB", "Seconds", "Lines/s", "MB/s", "Peak RSS", "Store", "Ratio", "Analyse"):
        table.add_column(column, justify="right")

    measurements: list[BenchmarkResult] = []
    try:
        with console.status("Measuring…") as status:
            for result in run_benchmark(
                sizes,
                scenario=scenario,
                seed=seed,
                workdir=workdir,
                on_start=lambda size: status.update(f"Measuring {size:,} lines…"),
            ):
                measurements.append(result)
                table.add_row(
                    f"{result.lines:,}",
                    f"{result.bytes_read / 1_048_576:,.1f}",
                    f"{result.ingest_seconds:,.2f}",
                    f"{result.lines_per_second:,.0f}",
                    f"{result.megabytes_per_second:,.1f}",
                    f"{result.peak_rss_mb:,.0f} MB",
                    f"{result.store_bytes / 1_048_576:,.1f} MB",
                    f"{result.compression_ratio:,.1f}x",
                    f"{result.analyse_seconds * 1000:,.0f} ms",
                )
    except BenchmarkError as exc:
        raise _fail(str(exc)) from exc
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)

    console.print(table)
    if measurements:
        slowest = min(result.lines_per_second for result in measurements)
        console.print(
            f"Reconstruction time is the cost of one question, and is paid per client; "
            f"ingest is paid once. Sustained at least {slowest:,.0f} lines/s."
        )
    if not keep:
        console.print("Working files removed. Pass --keep to inspect them.")

    if out is not None:
        out.write_text(
            json.dumps(
                {
                    "tool": f"logarc {__version__}",
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "scenario": scenario,
                    "seed": seed,
                    "runs": [result.to_dict() for result in measurements],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        console.print(f"Measurements written to {out}")


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
