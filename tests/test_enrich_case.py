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

from logarc.case import Case
from logarc.detect.crs.sidecar import CrsDetection, SidecarConfig
from logarc.enrich import EnrichProgress, enrich_case

if TYPE_CHECKING:
    from collections.abc import Iterable

    from logarc.core.event import NormalizedEvent

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
    monkeypatch.setattr("logarc.enrich.run_sidecar", replaying_everything)
    seen: list[EnrichProgress] = []

    enrich_case(a_case(tmp_path), report=seen.append, every=1)

    assert seen, "nothing reported"
    assert [step.replayed for step in seen] == [1, 2, 3, 4]
    assert {step.total for step in seen} == {4}


def test_stopping_keeps_what_was_already_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The promise the dialog makes, and the reason it can make it."""
    monkeypatch.setattr("logarc.enrich.run_sidecar", replaying_everything)
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
    monkeypatch.setattr("logarc.enrich.run_sidecar", replaying_everything)

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
    monkeypatch.setattr("logarc.enrich.run_sidecar", _recording(seen))
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
    applied when no config was passed, `logarc enrich` would quietly go on
    telling CRS the site is `localhost`."""
    seen: list[SidecarConfig] = []
    monkeypatch.setattr("logarc.enrich.run_sidecar", _recording(seen))
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
    monkeypatch.setattr("logarc.enrich.run_sidecar", _recording(seen))

    enrich_case(a_case(tmp_path))

    assert seen[0].host == "localhost"


def test_the_outcome_names_the_configuration_that_actually_ran(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not the one the caller passed in, which on a named case is a different one.

    The host is swapped in here, so a caller reporting its own config reports a
    run that did not happen: `logarc enrich` printed a fingerprint the case it
    had just written did not carry.
    """
    monkeypatch.setattr("logarc.enrich.run_sidecar", _recording([]))
    case_dir = a_case(tmp_path)
    with Case.open(case_dir) as case:
        case.set_site_hosts(["shop.test"])

    outcome = enrich_case(case_dir, config=SidecarConfig(paranoia=3))

    assert outcome.config.host == "shop.test"
    with Case.open(case_dir) as case:
        assert outcome.config.fingerprint() == case.manifest.config["crs_fingerprint"]
