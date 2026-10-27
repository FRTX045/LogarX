"""Enriching a case with CRS, watchably and stoppably.

The command line already did this, inline, with a spinner. The window needs the
same work with two things the spinner did not have to provide: a figure to draw
a bar from, and a way to stop that keeps what has been found. So the work moved
here and both callers share it — the rule being that anything the window can do
is also scriptable.

**Stopping does not raise, and that is the difference from ingest.** A cancelled
ingest raises `IngestCancelled` because a truncated case that looks complete is
the worst outcome available there. Enrichment only ever *adds* to a case, so a
partial result is a smaller true answer rather than a false one — it stops by
ending the stream cleanly, which is what lets the sidecar return the detections
it already has.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from logarx.case import Case
from logarx.detect.crs.sidecar import CrsDetection, SidecarConfig
from logarx.enrich import EnrichProgress, enrich_case

if TYPE_CHECKING:
    from collections.abc import Iterable

    from logarx.core.event import NormalizedEvent

START = datetime(2020, 10, 10, 13, 55, tzinfo=UTC)

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:37 +0000] "GET /b HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:38 +0000] "GET /c HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:39 +0000] "GET /d HTTP/1.1" 200 1 "-" "curl/8.0"',
]


def a_case(root: Path, *, lines: list[str] | None = None) -> Path:
    log = root / "access.log"
    log.write_text("\n".join(lines if lines is not None else LINES) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
        case.finalize()
    return root / "case"


def detection(line_no: int) -> CrsDetection:
    return CrsDetection(
        source_file_id="access.log",
        line_no=line_no,
        rule_id=942100,
        severity="critical",
        msg="SQL Injection",
        matched_var="ARGS:q",
        transformed_value="1' OR 1=1",
        attack_family="attack-sqli",
    )


def replaying_everything(events: Iterable[NormalizedEvent], **_: object) -> list[CrsDetection]:
    """A sidecar that reports one detection per request it is handed."""
    return [detection(one.evidence.line_no) for one in events]


def test_progress_carries_a_denominator_the_bar_can_be_drawn_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a total there is no bar, only a spinner.

    The command line could get away with one because a terminal has nowhere to
    draw a proportion. The manifest knows how many events were parsed, so the
    window does not have to guess or count first.
    """
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    seen: list[EnrichProgress] = []

    enrich_case(a_case(tmp_path), report=seen.append, every=1)

    assert seen, "nothing reported"
    assert [step.replayed for step in seen] == [1, 2, 3, 4]
    assert {step.total for step in seen} == {4}


def test_stopping_keeps_what_was_already_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The promise the dialog makes, and the reason it can make it."""
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case = a_case(tmp_path)

    seen = 0

    def after_two() -> bool:
        nonlocal seen
        seen += 1
        return seen > 2

    outcome = enrich_case(case, should_stop=after_two, every=1)

    assert outcome.stopped is True
    assert outcome.replayed == 2
    assert len(outcome.detections) == 2
    assert outcome.path.exists(), "a stopped run still writes what it found"


def test_a_finished_run_is_not_reported_as_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)

    outcome = enrich_case(a_case(tmp_path), every=1)

    assert outcome.stopped is False
    assert outcome.replayed == 4
    assert outcome.covered == 4


def test_an_empty_case_is_refused_rather_than_enriched(tmp_path: Path) -> None:
    """Reported as "ingest first" rather than as a missing sidecar.

    Checking afterwards would send somebody to build a Go binary when their real
    problem is that they have not read a log yet.
    """
    (tmp_path / "empty.log").write_text("", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.finalize()

    with pytest.raises(ValueError, match="ingest"):
        enrich_case(tmp_path / "case")


# -- the case's own host reaches CRS ------------------------------------------


def _recording(seen: list[SidecarConfig]):
    def fake(events, *, config, **_kwargs):
        seen.append(config)
        for _ in events:
            pass
        return []

    return fake


def test_crs_is_told_the_host_the_reader_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The fix for CRS 931130, and the reason it could be withheld at all.**

    931130 reads a URL in a parameter as off-domain unless it ends with
    `.<Host header>`. Apache does not log that header, so the sidecar invents
    one, and it used to be `localhost` for every case — so every outbound URL,
    the site's own asset host included, looked foreign. A case that has been
    told its domains now hands the real one over.
    """
    seen: list[SidecarConfig] = []
    monkeypatch.setattr("logarx.enrich.run_sidecar", _recording(seen))
    case_dir = a_case(tmp_path)
    with Case.open(case_dir) as case:
        case.set_site_hosts(["www.shop.test", "shop.test"])

    enrich_case(case_dir)

    assert [config.host for config in seen] == ["shop.test"]
    with Case.open(case_dir) as case:
        assert case.manifest.config["crs_host"] == "shop.test"


def test_the_host_comes_from_the_case_even_when_a_caller_builds_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The command line builds its own `SidecarConfig` for the paranoia level
    and the paths, and offers no way to set a host. If the case's answer only
    applied when no config was passed, `logarx-dev enrich` would quietly go on
    telling CRS the site is `localhost`."""
    seen: list[SidecarConfig] = []
    monkeypatch.setattr("logarx.enrich.run_sidecar", _recording(seen))
    case_dir = a_case(tmp_path)
    with Case.open(case_dir) as case:
        case.set_site_hosts(["shop.test"])

    enrich_case(case_dir, config=SidecarConfig(paranoia=3))

    assert seen[0].host == "shop.test"
    assert seen[0].paranoia == 3, "and nothing else the caller chose is overridden"


def test_a_case_that_named_nothing_keeps_the_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unanswered stays exactly as it was, which is also what keeps 931130
    withheld for it — the engine only trusts the rule when the host CRS was
    given is one the reader named."""
    seen: list[SidecarConfig] = []
    monkeypatch.setattr("logarx.enrich.run_sidecar", _recording(seen))

    enrich_case(a_case(tmp_path))

    assert seen[0].host == "localhost"


def test_the_outcome_names_the_configuration_that_actually_ran(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not the one the caller passed in, which on a named case is a different one.

    The host is swapped in here, so a caller reporting its own config reports a
    run that did not happen: `logarx-dev enrich` printed a fingerprint the case it
    had just written did not carry.
    """
    monkeypatch.setattr("logarx.enrich.run_sidecar", _recording([]))
    case_dir = a_case(tmp_path)
    with Case.open(case_dir) as case:
        case.set_site_hosts(["shop.test"])

    outcome = enrich_case(case_dir, config=SidecarConfig(paranoia=3))

    assert outcome.config.host == "shop.test"
    with Case.open(case_dir) as case:
        assert outcome.config.fingerprint() == case.manifest.config["crs_fingerprint"]


def test_a_rerun_tells_crs_the_case_s_own_site() -> None:
    """The window asks whether a case's CRS results are current by comparing how
    they were made with how a rerun would make them, so both have to come from
    one place. A case answered for `shop.test` was enriched with that host;
    compared against `localhost` it would always look out of date."""
    from logarx.enrich import crs_config

    assert crs_config(("shop.test",)).host == "shop.test"
    assert crs_config(()).host == SidecarConfig().host
    assert crs_config(("shop.test",), SidecarConfig(paranoia=3)).paranoia == 3


# -- a stopped run says it was one ---------------------------------------------


def stop_after(count: int):
    """A `should_stop` that lets `count` requests through."""
    asked = 0

    def should_stop() -> bool:
        nonlocal asked
        asked += 1
        return asked > count

    return should_stop


def test_a_stopped_run_is_remembered_as_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requests CRS never read look exactly like requests it read and passed. A
    case reopened later has to know which kind it holds, or a partial check
    reads as a clean one."""
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)

    enrich_case(case_dir, should_stop=stop_after(2))

    with Case.open(case_dir) as case:
        crs = case.crs_evidence()
    assert crs.fingerprint is not None
    assert crs.coverage == (2, 4)


def test_a_finished_run_is_remembered_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)

    enrich_case(case_dir)

    with Case.open(case_dir) as case:
        assert case.crs_evidence().coverage is None
        assert case.manifest.config["crs_replayed"] == 4
        assert case.manifest.config["crs_requests"] == 4
        assert case.manifest.config["crs_complete"] is True


def test_stopping_a_rerun_keeps_the_complete_result_it_would_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enrichment only adds to a case. A rerun stopped after one request would
    otherwise swap four requests' worth of findings for one."""
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)
    enrich_case(case_dir)
    with Case.open(case_dir) as case:
        before = dict(case.manifest.config)

    outcome = enrich_case(case_dir, should_stop=stop_after(1))

    assert outcome.stopped is True
    assert outcome.kept_earlier is True
    with Case.open(case_dir) as case:
        crs = case.crs_evidence()
        assert case.manifest.config == before, "the earlier run's record is left as it was"
    assert crs.coverage is None
    assert crs.index is not None
    assert len(crs.index) == 4


def test_stopping_a_rerun_of_a_partial_result_replaces_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing complete is at stake, so the newer run stands, and says how far
    it got."""
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)
    enrich_case(case_dir, should_stop=stop_after(1))

    outcome = enrich_case(case_dir, should_stop=stop_after(3))

    assert outcome.kept_earlier is False
    with Case.open(case_dir) as case:
        assert case.crs_evidence().coverage == (3, 4)


def test_partial_coverage_reaches_the_analysis_and_its_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Said in every deliverable built from the case, not only on the day the
    run was stopped."""
    from logarx.caseview import reconstruct_client
    from logarx.report.html import render_report

    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)
    enrich_case(case_dir, should_stop=stop_after(2))
    with Case.open(case_dir) as case:
        crs = case.crs_evidence()

    result = reconstruct_client(case_dir, "203.0.113.5", crs)

    assert result.crs_coverage == (2, 4)
    assert result.to_dict()["crs_coverage"] == {"replayed": 2, "requests": 4}
    page = render_report(result)
    assert "CRS coverage" in page
    assert "2 of 4 requests" in page


def test_complete_coverage_is_stated_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Present and empty, as `site_hosts` is: a missing key would read as a
    report written before the question existed."""
    from logarx.caseview import reconstruct_client

    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)
    enrich_case(case_dir)
    with Case.open(case_dir) as case:
        crs = case.crs_evidence()

    payload = reconstruct_client(case_dir, "203.0.113.5", crs).to_dict()

    assert "crs_coverage" in payload
    assert payload["crs_coverage"] is None


def test_completion_is_what_was_recorded_not_what_the_counts_suggest(tmp_path: Path) -> None:
    """The total comes from the manifest, and a manifest that disagreed with
    the store would otherwise turn a stopped run into a finished one, or the
    reverse."""
    from logarx.detect.crs.store import CrsEvidence, write_detections

    write_detections(tmp_path, [])
    stopped = {"crs_fingerprint": "f", "crs_replayed": 4, "crs_requests": 4}
    finished = {"crs_fingerprint": "f", "crs_replayed": 2, "crs_requests": 4}

    assert CrsEvidence.of(tmp_path, {**stopped, "crs_complete": False}).coverage == (4, 4)
    assert CrsEvidence.of(tmp_path, {**finished, "crs_complete": True}).coverage is None
    assert CrsEvidence.of(tmp_path, finished).coverage is None, "unrecorded reads as complete"


def test_a_rerun_does_not_hold_the_earlier_detections_while_it_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whether the earlier run finished is in the manifest. Loading its whole
    index to find out would hold it in memory beside the new one."""
    monkeypatch.setattr("logarx.enrich.run_sidecar", replaying_everything)
    case_dir = a_case(tmp_path)
    enrich_case(case_dir)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the earlier detection index was loaded")

    monkeypatch.setattr("logarx.detect.crs.store.load_detections", refuse)
    assert enrich_case(case_dir, should_stop=stop_after(1)).kept_earlier
