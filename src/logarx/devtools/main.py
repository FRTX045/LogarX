"""`logarx` command line entry point."""

from __future__ import annotations

import json
import platform
import shutil
import tempfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.table import Table

from logarx import __version__
from logarx.analysis import AnalysisPolicy
from logarx.case import Case, CaseError
from logarx.detect.crs import (
    AUTO_ENV,
    CrsUnavailableError,
    SidecarConfig,
    runs_by_default,
)
from logarx.detect.crs.setup import SetupError, setup_crs
from logarx.detect.crs.store import CrsEvidence
from logarx.detect.engine import RuleEngine
from logarx.detect.rulepacks import default_rules
from logarx.detect.rules import RulePackError
from logarx.detect.ruleset import build_rules
from logarx.devtools.support import console, errors, fail, path_line, safe_output
from logarx.enrich import EnrichOutcome, enrich_case
from logarx.episode.builder import EpisodePolicy
from logarx.evaluation.benchmark import BenchmarkError, BenchmarkResult, run_benchmark
from logarx.evaluation.crs_corpus import CorpusError, score_corpus
from logarx.evaluation.csic import CsicError, convert_csic
from logarx.evaluation.scoring import evaluate as score_case
from logarx.evaluation.truth import TruthError, read_truth
from logarx.ingest.parallel import DEFAULT_WORKERS
from logarx.ingest.pipeline import DEFAULT_MAX_LINE_BYTES, FormatDetectionError
from logarx.ingest.reader import LogSourceError
from logarx.parsers.library import FormatLibraryError, move_old_home
from logarx.parsers.registry import (
    UnknownFormatError,
    register_saved_formats,
)
from logarx.sessionize.segmenter import SessionPolicy
from logarx.storage.event_store import StoreStateError
from logarx.style import plural

if TYPE_CHECKING:
    pass

app = typer.Typer(
    name="logarx-dev",
    help="Developer tools: build cases from logs, and measure what LogarX gets right.",
    no_args_is_help=True,
    add_completion=False,
)
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
    coverage in the process. `build_rules` refuses an id already in force, so a
    pack that copies a bundled rule to edit it fails loudly instead of shadowing
    it.
    """
    if not rules:
        return None
    in_force = build_rules(extra_packs=rules)
    return RuleEngine(in_force.rules, described=in_force.described)


def _say_crs_coverage(coverage: tuple[int, int] | None, case: Path) -> None:
    """Warn that CRS read only part of `case`, when it did.

    On every run, as "CRS not consulted" is. The requests a stopped run never
    reached carry no CRS finding, which is also what a request CRS read and
    passed carries, so a result that does not say so overstates its coverage.
    """
    if coverage is None:
        return
    replayed, requests = coverage
    console.print(
        f"[yellow]CRS stopped part way[/yellow]: it read {replayed:,} of {requests:,} "
        "requests, and the rest carry no CRS findings. Run "
        f"[bold]logarx-dev enrich --case {case}[/bold] again to cover them."
    )


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
        console.print(f"LogarX {__version__}")
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
    """Developer tools: build cases from logs, and measure what LogarX gets right."""
    safe_output()
    move_old_home()
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
            "compressed or small logs, which cannot benefit. Defaults to the "
            "cores available, capped at four.",
        ),
    ] = DEFAULT_WORKERS,
    max_line_bytes: Annotated[
        int,
        typer.Option(
            "--max-line-bytes",
            min=1_024,
            help="Longest line to parse. Anything longer is quarantined and "
            "counted rather than read, because parsing one costs about 327 "
            "times its length in memory.",
        ),
    ] = DEFAULT_MAX_LINE_BYTES,
    site_host: Annotated[
        list[str] | None,
        typer.Option(
            "--site-host",
            help="A domain this site owns. Repeatable. It lets LogarX tell a "
            "link to your own site from a link somewhere else, which is the "
            "only thing separating remote file inclusion from an ordinary "
            "redirect. The window asks for it after a log is opened.",
        ),
    ] = None,
    crs: Annotated[
        bool | None,
        typer.Option(
            "--crs/--no-crs",
            help="Replay the new case through OWASP CRS once it is read. On "
            f"unless {AUTO_ENV}=off says otherwise; `logarx-dev enrich` runs it "
            "again later, at another paranoia level if wanted.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Read logs into a new case, then replay it through OWASP CRS.

    `--max-line-bytes` defaults to a megabyte, about 120 times the longest line
    Apache will write. No real log reaches it; a crafted one can, and parsing a
    16 MB line was measured holding 5.5 GB. A line over the limit is recorded in
    the quarantine with its length, so the case still accounts for every line.

    `--workers` parses the file in byte ranges across processes, and now
    defaults to the cores available, capped at four. Measured on an 84 MB log
    with four physical cores behind eight logical: four workers read it 2.61
    times faster for 2.98 times the memory, 326 MB to 969 MB. Six was 5% faster
    again for 38% more memory, and eight was *slower* than six — past the
    physical cores there is nothing left to win.

    The cap is what keeps the memory predictable on a machine much larger than
    this one. `--workers 1` returns to a single process, and a log under 32 MB
    or a compressed one is read sequentially whatever is asked for.
    """
    try:
        with Case.create(case) as opened:
            results = opened.ingest(
                logs,
                log_format=log_format,
                workers=workers,
                max_line_bytes=max_line_bytes,
            )
            if site_host:
                opened.set_site_hosts(site_host)
    except USER_ERRORS as exc:
        raise fail(str(exc)) from exc

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
    path_line(f"Case: {case}")

    quarantined = sum(result.lines_quarantined for result in results)
    if quarantined:
        path_line(
            f"[yellow]{plural(quarantined, 'line')} could not be parsed[/yellow] — "
            f"see {case / 'quarantine' / 'unparsed.jsonl'}"
        )

    wanted = crs if crs is not None else runs_by_default()
    if wanted and any(result.events_parsed for result in results):
        _enrich_after_ingest(case)


def _enrich_after_ingest(case: Path) -> None:
    """CRS on a case that has just been read, which is finished either way.

    Nothing here exits non-zero. The ingest the command was asked for has
    succeeded, and CRS only adds findings — so a missing sidecar is a notice and
    a failed run is a warning with the command that tries again. `logarx-dev enrich`
    is where CRS failing is a failure, because there it is the whole job.
    """
    config = SidecarConfig()
    try:
        config.check()
    except CrsUnavailableError as exc:
        console.print(
            "\n[yellow]CRS was not run[/yellow] — the case is complete without it. "
            f"Pass --no-crs, or set {AUTO_ENV}=off, to stop trying."
        )
        console.print(str(exc), style="dim", markup=False)
        return

    try:
        with console.status("Replaying requests through CRS…"):
            outcome = enrich_case(case, config=config)
    except (CrsUnavailableError, OSError, *USER_ERRORS) as exc:
        console.print("\n[yellow]CRS did not finish:[/yellow]", end=" ")
        console.print(str(exc), markup=False)
        path_line(f"The case is complete without it. To try again: logarx-dev enrich --case {case}")
        return

    console.print()
    _report_enrichment(outcome)


@app.command("score-crs")
def score_crs(
    corpus: Annotated[
        Path,
        typer.Option(
            "--corpus",
            help="The CRS regression corpus. Arrives with the ruleset clone, "
            "not with this package.",
        ),
    ] = Path("vendor/coreruleset/tests/regression/tests"),
    family: Annotated[
        list[str] | None,
        typer.Option("--family", help="CRS family to score, e.g. 933. Repeatable."),
    ] = None,
    rules: Annotated[list[Path] | None, RULES_OPTION] = None,
) -> None:
    """Score this project's detection rules against the OWASP CRS corpus.

    A question paper written by somebody else, for somebody else's tool, years
    before this project existed — which is what makes the number worth quoting.
    Rules measured only against payloads their own author chose are rules that
    have marked their own homework.

    **Two things about the figure, both of which make it softer than it looks.**

    Recall is over what an access log could *see*, never over every case. A
    combined log records the request line, the Referer and the User-Agent and
    nothing else, so a payload in a POST body is out of reach for any tool of
    this kind — counted apart rather than as a miss, because scoring those would
    measure the log format and print it as a score for the rules.

    And a case counts as caught when *any* hostile rule fires, without asking
    whether the category was right. The number is a ceiling, not a floor.
    """
    try:
        scores = score_corpus(
            corpus, engine=_rule_engine(rules) or RuleEngine(default_rules()), families=family
        )
    except (CorpusError, *USER_ERRORS) as exc:
        raise fail(str(exc)) from exc

    table = Table(title="Detection against the OWASP CRS corpus")
    table.add_column("Family")
    for column in ("Cases", "Should match", "Caught", "Recall", "Should not", "Fired", "Wrongly"):
        table.add_column(column, justify="right")
    for score in scores:
        table.add_row(
            f"{score.family} {score.name}",
            f"{score.cases:,}",
            f"{score.in_reach:,}",
            f"{score.caught:,}",
            f"{score.recall:.0%}" if score.in_reach else "—",
            f"{score.negatives:,}",
            f"{score.false_alarms:,}",
            f"{score.false_alarm_rate:.0%}" if score.negatives else "—",
        )
    console.print(table)

    out_of_reach = sum(score.out_of_reach for score in scores)
    unscored = sum(score.unscored for score in scores)
    console.print(
        f"[dim]{out_of_reach:,} cases carry their payload in a body or a header no "
        f"access log writes down. They are not misses — no tool reading a log can "
        f"reach them — so they are left out of both columns above."
        + (
            f" {unscored:,} more are checked some other way than by a request rule."
            if unscored
            else ""
        )
        + "[/dim]\n"
    )

    for score in scores:
        if score.fired_wrongly:
            console.print(
                f"[bold]{score.family} {score.name}[/bold] — fired on traffic CRS "
                f"certifies as harmless:"
            )
            for example in score.fired_wrongly:
                console.print(f"  [red]{example}[/red]")
            console.print()
        if not score.missed:
            continue
        console.print(f"[bold]{score.family} {score.name}[/bold] — what got through:")
        for example in score.missed:
            console.print(f"  [yellow]{example}[/yellow]")
        if score.by_rule:
            caught_by = ", ".join(f"{rule} x{n}" for rule, n in list(score.by_rule.items())[:3])
            console.print(f"  [dim]caught by: {caught_by}[/dim]")
        console.print()


@app.command()
def evaluate(
    case: Annotated[Path, typer.Option("--case", "-c", help="Case directory to read.")],
    truth: Annotated[Path, typer.Option("--truth", "-t", help="Ground truth for its log.")],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the full numbers as JSON.")
    ] = None,
    no_crs: Annotated[
        bool,
        typer.Option(
            "--no-crs",
            help="Score as though the case had never been enriched. Both numbers "
            "out of one case, so a native figure cannot be taken from a CRS run "
            "by accident.",
        ),
    ] = False,
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
            crs = CrsEvidence(index=None, fingerprint=None) if no_crs else opened.crs_evidence()
            report = score_case(
                opened.store,
                loaded,
                # The case's own engine, so a score reflects what this case is
                # actually configured to detect. Without it, `evaluate` scored a
                # ruleset that `analyze` on the same case would not have used.
                engine=opened.rule_engine(),
                policy=policy,
                crs=crs.index,
                crs_fingerprint=crs.fingerprint,
                crs_coverage=crs.coverage,
                on_client=lambda client: status.update(f"Scoring {client}…"),
            )
    except USER_ERRORS as exc:
        raise fail(str(exc)) from exc

    _say_crs_coverage(report.crs_coverage, case)

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
        # Sorted, and with a closing newline. One of these files is committed as
        # the drift gate, so it is regenerated whenever a rule changes — and a
        # writer that reshuffles 261 lines of unchanged values buries the one
        # line that moved. Sorting makes the diff say what actually changed.
        out.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        path_line(f"\nFull numbers written to {out}")


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
    """Turn the CSIC 2010 HTTP dataset into an access log LogarX can read."""
    if not normal and not anomalous:
        raise fail("give at least one --normal or --anomalous file")

    try:
        result = convert_csic(
            normal=normal or [],
            anomalous=anomalous or [],
            out=out,
            truth_path=truth,
            include_bodies=include_bodies,
        )
    except (CsicError, OSError) as exc:
        raise fail(str(exc)) from exc

    console.print(
        f"Wrote {result.requests:,} requests to {result.path} "
        f"({result.normal:,} ordinary, {result.anomalous:,} attacks, "
        f"{result.sessions:,} sessions)"
    )
    if result.truth_path is not None:
        path_line(f"Ground truth written to {result.truth_path}")
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

    # The work itself lives in `logarx.enrich`, shared with the window. It used
    # to be written out here, and the window growing a CRS button would have
    # meant a second copy of it — which is how two callers come to disagree
    # about what enrichment does.
    try:
        with console.status("Replaying requests through CRS…"):
            outcome = enrich_case(case, config=config)
    except ValueError as exc:
        raise fail(str(exc)) from exc
    except (CrsUnavailableError, *USER_ERRORS) as exc:
        # CRS is the whole job here, so what the sidecar said is shown, above
        # the line that says what happened: a report of the fault needs it.
        if said := getattr(exc, "detail", ""):
            errors.print(said, style="dim", markup=False, highlight=False)
        raise fail(str(exc)) from exc

    _report_enrichment(outcome)


@app.command("setup-crs")
def setup_crs_command() -> None:
    """Fetch the pinned OWASP CRS ruleset and build the sidecar, in a source checkout.

    Needs git, Go 1.25 or newer and a network connection, once; anything already
    in place is left alone. It ends by replaying a known payload, so a setup it
    reports as done is one that works. The packaged Windows application already
    carries CRS and has nothing to set up.
    """
    try:
        with console.status("Setting up OWASP CRS…"):
            said = setup_crs()
    except (SetupError, CrsUnavailableError, OSError) as exc:
        raise fail(str(exc)) from exc
    for line in said:
        console.print(line, markup=False)


def _report_enrichment(outcome: EnrichOutcome) -> None:
    """What a CRS run found, for `enrich` and for the run `ingest` makes.

    The configuration printed is the one that ran, which is not always the one
    asked for: `enrich_case` replaces the host with the case's own.
    """
    ran = outcome.config
    table = Table(title="CRS enrichment")
    table.add_column("Requests", justify="right")
    table.add_column("With a detection", justify="right")
    table.add_column("Detections", justify="right")
    table.add_column("Paranoia", justify="right")
    table.add_column("Rules/s", justify="right")
    table.add_row(
        f"{outcome.replayed:,}",
        f"{outcome.covered:,}",
        f"{len(outcome.detections):,}",
        str(ran.paranoia),
        f"{outcome.rate:,.0f}",
    )
    console.print(table)
    path_line(f"\nWritten to {outcome.path}")
    console.print(
        f"CRS {ran.revision() or 'unknown'}, configuration {ran.fingerprint()} — "
        "recorded in the case manifest so a finding can name what produced it."
    )


def _count_lines(log: Path) -> int:
    with log.open("rb") as handle:
        return sum(1 for _ in handle)


@app.command()
def benchmark(
    log: Annotated[Path, typer.Option("--log", help="An access log to measure on.")],
    lines: Annotated[
        list[int] | None,
        typer.Option("--lines", "-n", help="Measure the first N lines. Repeatable. Default: all."),
    ] = None,
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
    if not log.is_file():
        raise fail(f"{log} is not a file")
    sizes = lines or [_count_lines(log)]

    # Always work inside a directory of our own making, even when the user
    # named where to put it. Cleanup then removes only what this run created,
    # so pointing --work at somewhere that already has files in it is safe.
    root = Path(work) if work is not None else Path(tempfile.gettempdir())
    root.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="logarx-bench-", dir=root))

    table = Table(title=f"Ingest: {log.name}")
    table.add_column("Lines", justify="right")
    for column in ("MB", "Seconds", "Lines/s", "MB/s", "Peak RSS", "Store", "Ratio", "Analyse"):
        table.add_column(column, justify="right")

    measurements: list[BenchmarkResult] = []
    try:
        with console.status("Measuring…") as status:
            for result in run_benchmark(
                sizes,
                log=log,
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
        raise fail(str(exc)) from exc
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
                    "tool": f"LogarX {__version__}",
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "log": str(log),
                    "runs": [result.to_dict() for result in measurements],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        path_line(f"Measurements written to {out}")
