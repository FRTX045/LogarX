"""The synthetic log generator.

The generator is the yardstick, so it is held to a higher standard than the code
it measures: if it emits a line the real parser cannot read, or if two runs of
the same seed differ, every accuracy number downstream is meaningless.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from random import Random

import pytest

from logarc.core.activity import ActivityCategory
from logarc.core.evidence import EvidenceRef
from logarc.detect.engine import RequestView
from logarc.evaluation.generator import (
    SCENARIOS,
    GenerationError,
    generate,
    write_log,
)
from logarc.evaluation.scenarios import BROKEN_LINK_BROWSER, BROWSER
from logarc.evaluation.truth import read_truth
from logarc.parsers.registry import get_parser

START = datetime(2024, 5, 1, tzinfo=UTC)


def emitted(scenario: str, lines: int, seed: int = 1) -> list[tuple[str, object]]:
    return list(generate(scenario, lines=lines, seed=seed, start=START))


def test_every_scenario_emits_exactly_the_requested_number_of_lines() -> None:
    for scenario in SCENARIOS:
        assert len(emitted(scenario, 200)) == 200, scenario


def test_every_line_parses_with_the_real_apache_parser() -> None:
    """A generator that emits lines logarc cannot read proves nothing."""
    parser = get_parser("apache-combined")
    for scenario in SCENARIOS:
        for number, (text, _) in enumerate(emitted(scenario, 300), start=1):
            event = parser.parse_line(text, EvidenceRef("gen.log", number))
            assert event is not None, f"{scenario} line {number} unparseable: {text}"
            assert event.method is not None
            assert event.status is not None


def test_the_same_seed_reproduces_the_same_log() -> None:
    first = [text for text, _ in emitted("mixed", 400, seed=99)]
    second = [text for text, _ in emitted("mixed", 400, seed=99)]

    assert first == second


def test_a_different_seed_produces_a_different_log() -> None:
    first = [text for text, _ in emitted("mixed", 400, seed=1)]
    second = [text for text, _ in emitted("mixed", 400, seed=2)]

    assert first != second


def test_lines_are_emitted_in_time_order() -> None:
    """Actors are interleaved, so the merge must keep the file chronological."""
    parser = get_parser("apache-combined")
    stamps = [
        parser.parse_line(text, EvidenceRef("gen.log", number)).timestamp  # type: ignore[union-attr]
        for number, (text, _) in enumerate(emitted("mixed", 500), start=1)
    ]

    assert stamps == sorted(stamps)


def test_truth_records_number_the_lines_they_describe() -> None:
    records = [truth for _, truth in emitted("sqli_campaign", 250)]

    assert [item.line_no for item in records] == list(range(1, 251))


def test_truth_reports_the_client_that_the_line_belongs_to() -> None:
    parser = get_parser("apache-combined")
    for number, (text, truth) in enumerate(emitted("mixed", 300), start=1):
        event = parser.parse_line(text, EvidenceRef("gen.log", number))
        assert event is not None
        assert event.client_ip == truth.client_ip


def test_an_activity_instance_is_stable_while_the_activity_lasts() -> None:
    """One id per intended activity, so segmentation has something to score.

    An instance may hold several ordinary-use categories, because a page load
    is one activity however many kinds of request it is made of. It never
    holds a hostile category beside anything else: an attack is its own act.
    """
    per_client: dict[str, list[tuple[str, ActivityCategory]]] = {}
    for _, truth in emitted("sqli_campaign", 400):
        per_client.setdefault(truth.client_ip, []).append((truth.instance_id, truth.category))

    for steps in per_client.values():
        seen: dict[str, set[ActivityCategory]] = {}
        for instance, category in steps:
            seen.setdefault(instance, set()).add(category)
        for categories in seen.values():
            if any(category.is_hostile for category in categories):
                assert len(categories) == 1, categories
        # An id never reappears after another id has taken over.
        ordered = [instance for instance, _ in steps]
        first_seen = list(dict.fromkeys(ordered))
        assert ordered == sorted(ordered, key=first_seen.index)


ORDINARY_USE = {ActivityCategory.BROWSING, ActivityCategory.STATIC_ASSET, ActivityCategory.API_CALL}


def test_a_page_load_is_one_activity() -> None:
    """A page, the assets it pulls in and the cart call it fires are one thing
    the shopper did, and the truth says so at the grain the tool draws.

    Written from the client's intent, not from the episode builder's output: a
    shopper reading a page is doing one thing, and that is a fact about the
    script. It happens to be the grain `episode.builder` draws at, which is
    what lets the boundary score measure the segmenter rather than a policy.
    """
    per_client: dict[str, list[tuple[str, ActivityCategory]]] = {}
    for _, truth in emitted("normal_browsing", 5_000):
        per_client.setdefault(truth.client_ip, []).append((truth.instance_id, truth.category))

    joins = 0
    for steps in per_client.values():
        for (before_id, before), (after_id, after) in pairwise(steps):
            if before in ORDINARY_USE and after in ORDINARY_USE and before is not after:
                joins += 1
                assert before_id == after_id, (
                    f"{before.value} -> {after.value} began a new activity"
                )
    assert joins, "premise: the shoppers loaded pages with assets"


def test_ordinary_use_scripts_carry_one_activity_until_the_client_goes_away() -> None:
    """The shopper and the broken-link follower each do one thing, however
    many kinds of request it takes. Only a pause starts a new activity."""
    for role in (BROWSER, BROKEN_LINK_BROWSER):
        steps = list(role.build(Random(1)).steps)
        ordinary = [step for step in steps if step.category in ORDINARY_USE]
        assert len({step.activity for step in ordinary}) == 1, role.name


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("normal_browsing", ActivityCategory.BROWSING),
        ("wordpress_scan", ActivityCategory.ENUMERATION),
        ("sqli_campaign", ActivityCategory.INJECTION),
        ("brute_force", ActivityCategory.CREDENTIAL_ATTACK),
        ("path_traversal", ActivityCategory.PATH_TRAVERSAL),
    ],
)
def test_a_scenario_contains_the_behaviour_it_is_named_after(
    scenario: str, expected: ActivityCategory
) -> None:
    categories = {truth.category for _, truth in emitted(scenario, 600)}

    assert expected in categories


def test_normal_browsing_contains_nothing_hostile() -> None:
    """The false-positive half of the evaluation needs clean traffic."""
    for _, truth in emitted("normal_browsing", 1000):
        assert not truth.category.is_hostile, truth


def test_browser_like_enumerators_send_a_plausible_referer() -> None:
    parser = get_parser("apache-combined")
    enumerated = []
    for number, (text, truth) in enumerate(emitted("wordpress_scan", 2_000), start=1):
        if truth.category is not ActivityCategory.ENUMERATION:
            continue
        event = parser.parse_line(text, EvidenceRef("gen.log", number))
        assert event is not None
        enumerated.append(event)

    assert enumerated
    assert all(event.referer == "https://shop.example.com/" for event in enumerated)


@pytest.mark.parametrize("scenario", ["normal_browsing", "mixed"])
def test_browsing_workloads_contain_realistic_broken_links(scenario: str) -> None:
    parser = get_parser("apache-combined")
    broken_by_client: dict[str, list[object]] = {}
    for number, (text, truth) in enumerate(emitted(scenario, 3_000), start=1):
        event = parser.parse_line(text, EvidenceRef("gen.log", number))
        assert event is not None
        if truth.category is ActivityCategory.BROWSING and event.status == 404:
            broken_by_client.setdefault(truth.client_ip, []).append(event)

    sequences = [events for events in broken_by_client.values() if len(events) >= 5]
    assert sequences
    for events in sequences:
        assert len({event.path for event in events}) >= 5
        assert not any(RequestView(event).is_static_asset for event in events)
        assert all(
            event.referer and event.referer.startswith("https://shop.example.com/")
            for event in events
        )


def test_mixed_carries_both_ordinary_and_hostile_clients() -> None:
    categories = {truth.category for _, truth in emitted("mixed", 2000)}

    assert any(category.is_hostile for category in categories)
    assert any(not category.is_hostile for category in categories)


def test_clients_go_away_and_come_back() -> None:
    """Both segmentation thresholds exist for pauses. A corpus with none in it
    cannot exercise either, which a threshold sweep found the hard way: every
    setting of the episode gap and the idle timeout produced identical scores,
    because no client had ever paused for longer than a minute.
    """
    parser = get_parser("apache-combined")
    last: dict[str, datetime] = {}
    longest: dict[str, float] = {}
    for number, (text, truth) in enumerate(emitted("mixed", 20_000), start=1):
        event = parser.parse_line(text, EvidenceRef("gen.log", number))
        assert event is not None
        previous = last.get(truth.client_ip)
        if previous is not None:
            gap = (event.timestamp - previous).total_seconds()
            longest[truth.client_ip] = max(longest.get(truth.client_ip, 0.0), gap)
        last[truth.client_ip] = event.timestamp

    gaps = sorted(longest.values(), reverse=True)
    assert any(gap > 300 for gap in gaps), "nothing exceeds the default episode gap"
    assert any(gap > 1800 for gap in gaps), "nothing exceeds the default idle timeout"


def test_coming_back_after_a_pause_is_a_new_activity() -> None:
    """Truth says so because the client went away, not because of a threshold.

    Deciding it by a gap size would make the sweep circular: the truth would
    agree with whatever setting the tool happened to be using.
    """
    per_client: dict[str, list[tuple[str, str]]] = {}
    for _, truth in emitted("normal_browsing", 20_000):
        per_client.setdefault(truth.client_ip, []).append((truth.instance_id, truth.category.value))

    resumed = [
        steps
        for steps in per_client.values()
        # A client that read a page, paused, and read another has two browsing
        # instances that are not adjacent to each other.
        if len({instance for instance, category in steps if category == "browsing"}) > 1
    ]
    assert resumed


def test_an_unknown_scenario_lists_the_ones_that_exist() -> None:
    with pytest.raises(GenerationError, match="sqli_campaign"):
        list(generate("does_not_exist", lines=10, seed=1, start=START))


def test_write_log_writes_the_log_and_its_truth(tmp_path: Path) -> None:
    log = tmp_path / "sample.log"

    result = write_log(
        log, scenario="mixed", lines=150, seed=5, truth_path=tmp_path / "sample.truth.jsonl"
    )

    assert result.lines == 150
    assert result.bytes_written == log.stat().st_size
    assert len(log.read_text(encoding="utf-8").splitlines()) == 150

    truth = read_truth(tmp_path / "sample.truth.jsonl")
    assert truth.scenario == "mixed"
    assert truth.seed == 5
    assert truth.source_file_id == "sample.log"
    assert truth.line_count == 150


def test_write_log_can_skip_truth_for_benchmark_sized_inputs(tmp_path: Path) -> None:
    """At ten million lines the truth file is the expensive part, and unused."""
    log = tmp_path / "big.log"

    result = write_log(log, scenario="mixed", lines=50, seed=1, truth_path=None)

    assert result.truth_path is None
    assert not list(tmp_path.glob("*.truth.jsonl"))
    assert result.lines == 50
