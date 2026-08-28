"""`logarc` command line entry point."""

from __future__ import annotations

import json
import platform
import shutil
import tempfile
from dataclasses import replace
from datetime import timedelta
from itertools import chain, islice
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING, Annotated, Final

import typer
from rich.console import Console
from rich.table import Table

from logarc import __version__
from logarc.analysis import AnalysisPolicy, analyse_ip
from logarc.case import Case, CaseError
from logarc.core.activity import Severity
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs import (
    CrsUnavailableError,
    SidecarConfig,
    run_sidecar,
    write_detections,
)
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.detect.rules import RulePackError, load_rules
from logarc.episode.builder import EpisodePolicy
from logarc.evaluation.benchmark import BenchmarkError, BenchmarkResult, run_benchmark
from logarc.evaluation.csic import CsicError, convert_csic
from logarc.evaluation.generator import DEFAULT_SEED, describe_scenarios, write_log
from logarc.evaluation.scoring import evaluate as score_case
from logarc.evaluation.truth import TruthError, read_truth
from logarc.gui.style import plural
from logarc.ingest.pipeline import FormatDetectionError
from logarc.ingest.reader import LogSourceError, open_log
from logarc.parsers.library import (
    FormatLibraryError,
    library_path,
    load_library,
    save_library,
)
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.registry import (
    UnknownFormatError,
    get_spec,
    is_built_in,
    register_saved_formats,
    registered_formats,
)
from logarc.parsers.spec import LogFormatSpec
from logarc.report import export as export_formats
from logarc.sessionize.segmenter import SessionPolicy
from logarc.storage.event_store import SORT_KEYS, StoreStateError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from logarc.core.event import NormalizedEvent

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
#:
#: `StoreStateError` is here because an unfinished case is a situation, not a
#: bug: cancelling an ingest leaves one deliberately, so that what was read is
#: not thrown away, and the window tells the investigator it "cannot be
#: analysed". Without it every command that reads a case — `list-ips`,
#: `analyze`, `evidence`, `export`, `enrich` — answered that with a traceback.
USER_ERRORS = (
    CaseError,
    FormatDetectionError,
    LogSourceError,
    RulePackError,
    StoreStateError,
    TruthError,
    UnknownFormatError,
    ValueError,
)


def _fail(message: str) -> typer.Exit:
    errors.print(f"[red]error:[/red] {message}", soft_wrap=True)
    return typer.Exit(code=1)


def _path_line(message: str) -> None:
    """Print a line carrying a path, without breaking the path.

    Rich wraps to the console width, and a path offers no spaces to break at, so
    a long one is cut mid-word — `...Desktop-BlackHa` on one line and `t\\...` on
    the next. Every path this tool prints is the argument to the next command,
    and one that cannot be copied out of the terminal is one the reader has to
    retype. `soft_wrap` leaves the line whole and lets the terminal fold it,
    which is the difference between a display that wraps and text that has had
    newlines put through it.
    """
    console.print(message, soft_wrap=True)


#: Shared by every command that applies rules, so a report cannot disagree with
#: the analysis it came from because one of them was given a different pack.
RULES_OPTION = typer.Option(
    "--rules",
    "-r",
    help="Extra rule pack (file or directory). Repeatable. Adds to the bundled packs.",
)


def _rule_engine(rules: list[Path] | None) -> RuleEngine | None:
    """Build an engine from extra packs, or None to use the bundled ones.

    Extra packs are added to the defaults rather than replacing them: someone
    writing one rule about their own application should not silently lose OWASP
    coverage in the process. `load_rules` refuses a duplicate id, so a pack that
    copies a bundled rule to edit it fails loudly instead of shadowing it.
    """
    if not rules:
        return None
    return RuleEngine([*default_rules(), *load_rules(list(rules))])


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


def _install_saved_formats() -> None:
    """Make the user's saved formats resolvable by name, for this run.

    A damaged library is reported and then stepped over rather than raised. It
    is the user's own editable file; breaking it should cost them their saved
    formats for the moment, not the ability to open a case they already have.
    A command that then cannot resolve a name says so in its own words, and the
    warning above it explains why.
    """
    try:
        register_saved_formats()
    except FormatLibraryError as exc:
        errors.print(f"[yellow]warning:[/yellow] saved formats not loaded: {exc}", soft_wrap=True)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Reconstruct what an IP did on a web server, from its access logs."""
    _install_saved_formats()


@app.command()
def ingest(
    logs: Annotated[list[Path], typer.Argument(help="Log files to read.")],
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to create.")],
    log_format: Annotated[
        str | None,
        typer.Option("--format", "-f", help="Log format name. Detected automatically if omitted."),
    ] = None,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            "-w",
            min=1,
            help="Processes to parse with. Trades memory for speed; ignored for "
            "compressed or small logs, which cannot benefit.",
        ),
    ] = 1,
) -> None:
    """Read logs into a new case.

    `--workers` above one parses the file in byte ranges across processes.
    Parsing is where ingest spends its time, and it parallelises cleanly, but
    each worker holds a batch of its own — so memory rises roughly in step with
    the count. It defaults to one because the memory is the user's to spend.
    """
    try:
        with Case.create(case) as opened:
            results = opened.ingest(logs, log_format=log_format, workers=workers)
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    # The path goes under the table rather than in its title: a title is centred
    # and wrapped, so a long path arrived as three fragments padded with spaces.
    # This is the path every later command is given, so it is the one that most
    # needs to survive being copied.
    table = Table(title="Ingested")
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
    _path_line(f"Case: {case}")

    quarantined = sum(result.lines_quarantined for result in results)
    if quarantined:
        _path_line(
            f"[yellow]{plural(quarantined, 'line')} could not be parsed[/yellow] — "
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

    table = Table(title="Clients")
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
    _path_line(f"Case: {case}")


@app.command()
def analyze(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    ip: Annotated[str, typer.Option("--ip", help="Client address to reconstruct.")],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the graph as JSON to this path.")
    ] = None,
    rules: Annotated[list[Path] | None, RULES_OPTION] = None,
) -> None:
    """Reconstruct one client's activity as a graph."""
    try:
        engine = _rule_engine(rules)
        with Case.open(case) as opened:
            crs = opened.crs_evidence()
            result = analyse_ip(
                opened.store,
                ip,
                engine=engine,
                crs=crs.index,
                crs_fingerprint=crs.fingerprint,
            )
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if result.crs_fingerprint is None:
        # Said out loud on every run, not once at enrich time. The same log
        # analysed on a machine without the sidecar yields a different answer,
        # and a forensic result that does not say so is the failure mode this
        # warning exists to prevent.
        console.print(
            "[yellow]CRS not consulted[/yellow] — signature coverage is the bundled rules "
            f"alone. Run [bold]logarc enrich --case {case}[/bold] to add it."
        )

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
        f"{result.request_count:,} requests across {plural(len(result.sessions), 'session')} "
        f"reduced to {len(result.episodes)} activities."
    )

    if out is not None:
        out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        _path_line(f"Graph written to {out}")


@app.command()
def evidence(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    ip: Annotated[str, typer.Option("--ip", help="Client address to show evidence for.")],
    episode: Annotated[
        str | None, typer.Option("--episode", "-e", help="Show only this activity.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="Source lines to show per activity.")
    ] = 10,
    rules: Annotated[list[Path] | None, RULES_OPTION] = None,
) -> None:
    """Show the raw log lines behind a client's reconstructed activity.

    The other half of the chain of custody: `analyze` says what happened, this
    says which lines say so.
    """
    try:
        engine = _rule_engine(rules)
        with Case.open(case) as opened:
            crs = opened.crs_evidence()
            result = analyse_ip(
                opened.store,
                ip,
                engine=engine,
                crs=crs.index,
                crs_fingerprint=crs.fingerprint,
            )
            episodes = result.episodes
            if episode is not None:
                episodes = tuple(item for item in episodes if item.episode_id == episode)
                if not episodes:
                    known = ", ".join(item.episode_id for item in result.episodes) or "none"
                    raise _fail(f"no activity {episode!r} for {ip}; this client has: {known}")
            lines = {
                item.episode_id: opened.read_evidence(item.evidence[:limit]) for item in episodes
            }
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if not episodes:
        console.print(f"[yellow]No activity found for {ip} in this case.[/yellow]")
        return

    for item in episodes:
        console.print(
            f"\n[bold]{item.episode_id}[/bold]  "
            f"[{_SEVERITY_STYLE[item.severity]}]{item.label}[/]  "
            f"{item.request_count:,} requests, outcome {item.outcome.value}"
        )
        for line in lines[item.episode_id]:
            if line.available:
                marker = "" if line.verified else " [yellow](source changed since ingest)[/yellow]"
                console.print(f"  [dim]{line.ref}[/dim]{marker}")
                console.print(f"    {line.text}", highlight=False)
            else:
                console.print(f"  [dim]{line.ref}[/dim] [yellow]unavailable[/yellow]")
                if line.note:
                    console.print(f"    [yellow]{line.note}[/yellow]")
        if item.evidence_total > len(lines[item.episode_id]):
            console.print(
                f"  [dim]… {item.evidence_total - len(lines[item.episode_id]):,} more lines "
                f"in this activity[/dim]"
            )


@app.command()
def export(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    ip: Annotated[str, typer.Option("--ip", help="Client address to report on.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="File to write.")],
    output_format: Annotated[str, typer.Option("--format", "-f", help="html or json.")] = "html",
    rules: Annotated[list[Path] | None, RULES_OPTION] = None,
) -> None:
    """Write a standalone report for one client."""
    # Checked before the case is opened, so a typo costs nothing but the typo.
    try:
        export_formats.named(output_format)
    except ValueError as exc:
        raise _fail(str(exc)) from exc

    try:
        engine = _rule_engine(rules)
        with Case.open(case) as opened:
            crs = opened.crs_evidence()
            result = analyse_ip(
                opened.store,
                ip,
                engine=engine,
                crs=crs.index,
                crs_fingerprint=crs.fingerprint,
            )
            manifest = opened.manifest
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    export_formats.write_reconstruction(result, manifest, kind=output_format, target=out)
    _path_line(f"Report written to {out}")


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
        _path_line(f"Ground truth written to {result.truth_path}")


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
                crs=opened.crs_evidence().index,
                on_client=lambda client: status.update(f"Scoring {client}…"),
            )
    except USER_ERRORS as exc:
        raise _fail(str(exc)) from exc

    if not report.binary.total:
        console.print("[yellow]Nothing to score: no truth line matched a stored event.[/yellow]")
        return

    if report.classification is not None:
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
    else:
        console.print(
            f"[yellow]{report.scenario}[/yellow] only records whether a request was an "
            "attack, not which kind, so there is no per-activity table to show."
        )

    hostile = report.binary
    if hostile.has_attacks:
        console.print(
            f"\n[bold]Attack or not[/bold] precision {hostile.precision:.3f}   "
            f"recall {hostile.recall:.3f}   F1 {hostile.f1:.3f}   "
            f"false alarms {hostile.false_positive_rate:.3%} of ordinary traffic\n"
            f"{hostile.true_positives:,} caught, {hostile.false_negatives:,} missed, "
            f"{hostile.false_positives:,} raised in error, over {hostile.total:,} requests."
        )
    else:
        # Precision and recall are 0/0 here. Printing them would report a clean
        # corpus as total detection failure, which is the opposite of what it is.
        console.print(
            f"\n[bold]Attack or not[/bold] no hostile traffic in this log, so "
            f"precision and recall do not apply.\n"
            f"false alarms {hostile.false_positive_rate:.3%} — "
            f"{hostile.false_positives:,} raised in error over {hostile.total:,} "
            f"ordinary requests."
        )

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
        _path_line(f"\nFull numbers written to {out}")


@app.command("convert-csic")
def convert_csic_command(
    out: Annotated[Path, typer.Option("--out", "-o", help="Access log to write.")],
    normal: Annotated[
        list[Path] | None,
        typer.Option("--normal", help="CSIC file of ordinary traffic. Repeatable."),
    ] = None,
    anomalous: Annotated[
        list[Path] | None,
        typer.Option("--anomalous", help="CSIC file of attack traffic. Repeatable."),
    ] = None,
    truth: Annotated[
        Path | None, typer.Option("--truth", "-t", help="Write the ground truth here.")
    ] = None,
    include_bodies: Annotated[
        bool,
        typer.Option(
            "--include-bodies",
            help="Fold POST bodies into the query. Off by default: a real access log has none.",
        ),
    ] = False,
) -> None:
    """Turn the CSIC 2010 HTTP dataset into an access log logarc can read."""
    if not normal and not anomalous:
        raise _fail("give at least one --normal or --anomalous file")

    try:
        result = convert_csic(
            normal=normal or [],
            anomalous=anomalous or [],
            out=out,
            truth_path=truth,
            include_bodies=include_bodies,
        )
    except (CsicError, OSError) as exc:
        raise _fail(str(exc)) from exc

    console.print(
        f"Wrote {result.requests:,} requests to {result.path} "
        f"({result.normal:,} ordinary, {result.anomalous:,} attacks, "
        f"{result.sessions:,} sessions)"
    )
    if result.truth_path is not None:
        _path_line(f"Ground truth written to {result.truth_path}")
    if result.attacks_hidden_in_bodies and not include_bodies:
        console.print(
            f"[yellow]{result.attacks_hidden_in_bodies:,} attacks "
            f"({1 - result.visible_attack_ratio:.0%}) carry their payload only in a POST "
            "body.[/yellow] A web server access log records the request line and nothing "
            "after it, so those are invisible to any tool that reads one. Recall measured "
            f"here cannot exceed {result.visible_attack_ratio:.0%}."
        )
    console.print(
        "\nThe traces carry no responses, so status is written as 200 throughout: "
        "outcome cannot be evaluated on this dataset."
    )


@app.command()
def enrich(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to enrich.")],
    paranoia: Annotated[
        int, typer.Option("--paranoia", min=1, max=4, help="CRS paranoia level.")
    ] = 2,
    rules_dir: Annotated[
        Path | None,
        typer.Option("--crs-rules", help="Path to a coreruleset clone."),
    ] = None,
    binary: Annotated[
        Path | None, typer.Option("--sidecar", help="Path to a built crs-sidecar binary.")
    ] = None,
) -> None:
    """Add OWASP CRS detections to a case.

    The bundled rules classify behaviour; CRS enumerates payload syntax, which
    is a different job and one it does far better. Enriching runs every stored
    request past CRS once and keeps the result in the case, so later analyses
    read it rather than paying for it again.

    A CRS detection never overrides a rule packed here. It only names requests
    that would otherwise be reported as ordinary traffic.
    """
    defaults = SidecarConfig()
    config = SidecarConfig(
        binary=binary or defaults.binary,
        rules=rules_dir or defaults.rules,
        paranoia=paranoia,
    )

    # Counted while streaming rather than by taking a length first. `enrich` is
    # the one command that reads a whole case, so it is the one command where
    # materialising the events would put the corpus in memory — which is exactly
    # what `EventStore.all_events()` streams to avoid.
    replayed = 0

    def counting(source: Iterable[NormalizedEvent]) -> Iterator[NormalizedEvent]:
        nonlocal replayed
        for stored in source:
            replayed += 1
            yield stored

    try:
        with Case.open(case) as opened:
            stream = opened.store.all_events()
            # One event is pulled to tell an empty case from a full one, then put
            # back. Checking after the run instead would report a missing sidecar
            # to someone whose real problem is that they have not ingested yet.
            first = next(stream, None)
            if first is None:
                raise _fail(f"no events in {case}; ingest a log first")

            with console.status("Replaying requests through CRS…"):
                started = perf_counter()
                detections = run_sidecar(counting(chain([first], stream)), config=config)
                elapsed = perf_counter() - started

            path = write_detections(opened.root, detections)
            opened.manifest.config.update(config.as_config())
            opened.manifest.save(opened.root)
    except (CrsUnavailableError, *USER_ERRORS) as exc:
        raise _fail(str(exc)) from exc

    covered = len({(item.source_file_id, item.line_no) for item in detections})
    rate = replayed / elapsed if elapsed else 0.0

    table = Table(title="CRS enrichment")
    table.add_column("Requests", justify="right")
    table.add_column("With a detection", justify="right")
    table.add_column("Detections", justify="right")
    table.add_column("Paranoia", justify="right")
    table.add_column("Rules/s", justify="right")
    table.add_row(
        f"{replayed:,}",
        f"{covered:,}",
        f"{len(detections):,}",
        str(config.paranoia),
        f"{rate:,.0f}",
    )
    console.print(table)
    _path_line(f"\nWritten to {path}")
    console.print(
        f"CRS {config.revision() or 'unknown'}, configuration {config.fingerprint()} — "
        "recorded in the case manifest so a finding can name what produced it."
    )


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
        _path_line(f"Measurements written to {out}")


formats_app = typer.Typer(
    help="See, write and try out log formats.",
    invoke_without_command=True,
    add_completion=False,
)
app.add_typer(formats_app, name="formats")


@formats_app.callback(invoke_without_command=True)
def formats(ctx: typer.Context) -> None:
    """List the log formats that can be parsed.

    Kept as the group's own behaviour rather than a `list` subcommand, so that
    `logarc formats` keeps doing what it did before there were subcommands.
    """
    if ctx.invoked_subcommand is not None:
        return

    table = Table(title="Known log formats")
    table.add_column("Name")
    table.add_column("Source")
    table.add_column("Definition")
    for entry in registered_formats():
        table.add_row(
            entry.name,
            "built-in" if is_built_in(entry.name) else "saved",
            entry.description,
        )
    console.print(table)
    console.print(
        "\nWrite one with [bold]logarc formats add <name> '<directive>'[/bold], and try a "
        "directive against a real log first with [bold]logarc formats check[/bold]."
    )
    _path_line(f"Saved formats: {library_path()}")


@formats_app.command("add")
def formats_add(
    name: Annotated[str, typer.Argument(help="What to call this format.")],
    directive: Annotated[str, typer.Argument(help="The Apache LogFormat directive string.")],
    note: Annotated[
        str, typer.Option("--note", help="A reminder of what this format is for.")
    ] = "",
    replace: Annotated[
        bool, typer.Option("--replace", help="Overwrite a saved format of the same name.")
    ] = False,
) -> None:
    """Save a log format so later cases can be ingested with it by name."""
    saved = _load_or_fail()
    existing = {spec.name for spec in saved}

    if is_built_in(name):
        raise _fail(
            f"{name!r} is a built-in format. Built-ins are matched first, so a saved "
            "format of the same name would never be reached; pick another name."
        )
    if name in existing and not replace:
        raise _fail(f"{name!r} is already saved; pass --replace to overwrite it")

    spec = LogFormatSpec(name=name, directive=directive, description=note)
    kept = [item for item in saved if item.name != name]
    try:
        save_library([*kept, spec])
    except FormatLibraryError as exc:
        raise _fail(str(exc)) from exc

    console.print(f"Saved [bold]{name}[/bold]: {directive}")
    _path_line(f"Saved formats: {library_path()}")


@formats_app.command("remove")
def formats_remove(
    name: Annotated[str, typer.Argument(help="The saved format to remove.")],
) -> None:
    """Forget a saved log format.

    Cases already ingested with it are unaffected: each carries its own copy of
    the definition and goes on reading exactly as it did.
    """
    saved = _load_or_fail()
    if name not in {spec.name for spec in saved}:
        if is_built_in(name):
            raise _fail(f"{name!r} is a built-in format and cannot be removed")
        raise _fail(f"no saved format named {name!r}")

    save_library([spec for spec in saved if spec.name != name])
    console.print(f"Removed [bold]{name}[/bold].")


@formats_app.command("show")
def formats_show(
    name: Annotated[str, typer.Argument(help="The format to describe.")],
) -> None:
    """Print the definition behind a format's name."""
    try:
        spec = get_spec(name)
    except UnknownFormatError as exc:
        raise _fail(str(exc)) from exc
    if spec is None:
        raise _fail(f"{name!r} was registered from code and has no definition to show")

    table = Table(title=f"Log format {name}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Kind", spec.kind)
    table.add_row("Source", "built-in" if is_built_in(name) else "saved")
    table.add_row("Definition", spec.summary)
    if spec.description:
        table.add_row("Note", spec.description)
    console.print(table)


@formats_app.command("check")
def formats_check(
    directive: Annotated[str, typer.Argument(help="The LogFormat directive to try.")],
    log: Annotated[Path, typer.Option("--log", help="A log file to try it against.")],
    lines: Annotated[int, typer.Option("--lines", min=1, help="How many lines to read.")] = 5,
) -> None:
    """Try a directive against a real log and show what it pulls out.

    Writing a directive blind is guesswork, and a wrong one does not announce
    itself — it quarantines every line and presents as an empty case. This is
    the answer to that: look at the fields before saving anything.
    """
    try:
        parser = LogFormatSpec(name="check", directive=directive).build()
    except LogFormatError as exc:
        raise _fail(str(exc)) from exc

    try:
        with open_log(log) as stream:
            sample = [(number, text) for number, text in islice(stream, lines) if text.strip()]
    except LogSourceError as exc:
        raise _fail(str(exc)) from exc

    table = Table(title=f"{directive}  ·  {log.name}")
    for column in ("Line", "Client", "When", "Method", "Path", "Status"):
        table.add_column(column)

    parsed = 0
    for number, text in sample:
        event = parser.parse_line(text, EvidenceRef(log.name, number))
        if event is None:
            table.add_row(str(number), "[red]did not match[/red]", "", "", "", "")
            continue
        parsed += 1
        table.add_row(
            str(number),
            event.client_ip,
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event.method or "",
            event.path or "",
            str(event.status) if event.status is not None else "",
        )
    console.print(table)
    console.print(f"Read [bold]{parsed} of {len(sample)}[/bold] lines.")

    if parsed == 0:
        raise _fail("this directive reads nothing in that log; the fields are in another order")


def _load_or_fail() -> list[LogFormatSpec]:
    try:
        return load_library()
    except FormatLibraryError as exc:
        raise _fail(str(exc)) from exc
