"""End-to-end tests for the reconstruction pipeline.

These drive the whole engine — parse, store, sessionize, label, segment,
graph — against logs written to look like real attacker behaviour. If the story
these produce is wrong, the tool is wrong regardless of what the unit tests say.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.analysis import AnalysisPolicy, analyse_ip
from logarc.case import Case
from logarc.core.activity import ActivityCategory, Outcome
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.episode.builder import EpisodePolicy

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
ATTACKER = "203.0.113.66"
AGENT = "Mozilla/5.0 (X11; Linux x86_64)"


def line(
    *,
    seconds: int,
    target: str,
    status: int = 200,
    ip: str = ATTACKER,
    agent: str = AGENT,
    size: int = 512,
) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{when}] "GET {target} HTTP/1.1" {status} {size} "-" "{agent}"'


def build_case(tmp_path: Path, lines: list[str]) -> Case:
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return Case.open(tmp_path / "case")


@pytest.fixture
def campaign(tmp_path: Path) -> Case:
    """A recognisable attack: look around, enumerate, inject, then read data."""
    lines: list[str] = []
    at = 0

    # Ordinary browsing first.
    for path in ("/", "/products", "/products/shoes", "/assets/app.css"):
        lines.append(line(seconds=at, target=path))
        at += 20

    # Configuration probing.
    for path in ("/.env", "/.git/config", "/backup.sql", "/phpinfo.php"):
        lines.append(line(seconds=at, target=path, status=404, size=0))
        at += 2

    # A pause longer than the slow sweep's five minutes. Run straight into the
    # sweep, the probes would be its first wordlist entries instead — see
    # `test_probes_that_run_straight_into_a_sweep_are_its_first_entries`.
    at += 360

    # Directory enumeration: a wordlist against a 404 wall.
    for index in range(30):
        lines.append(line(seconds=at, target=f"/admin/{index}", status=404, size=0))
        at += 1

    # Injection probing, refused.
    for payload in (
        "id=1%27%20OR%20%271%27%3D%271",
        "id=1%20UNION%20SELECT%20NULL",
        "id=1%3B%20DROP%20TABLE%20users--",
    ):
        lines.append(line(seconds=at, target=f"/product?{payload}", status=403, size=0))
        at += 3

    # Injection that worked, returning a large response.
    lines.append(
        line(
            seconds=at,
            target="/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
            status=200,
            size=1_400_000,
        )
    )
    at += 5

    # Unrelated traffic from someone else, to prove isolation.
    lines.append(line(seconds=at, target="/", ip="198.51.100.1", agent="curl/8.0"))

    return build_case(tmp_path, lines)


def test_the_reconstruction_reads_as_a_sequence(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    categories = [episode.category for episode in result.episodes]

    assert ActivityCategory.RECONNAISSANCE in categories
    assert ActivityCategory.ENUMERATION in categories
    assert ActivityCategory.INJECTION in categories
    assert categories.index(ActivityCategory.RECONNAISSANCE) < categories.index(
        ActivityCategory.INJECTION
    )


def test_probes_that_run_straight_into_a_sweep_are_its_first_entries(tmp_path: Path) -> None:
    """Four named files two seconds apart, then thirty misses: from the log alone
    that is a wordlist beginning with `/.env`, and the sweep names all of it. The
    probes stay among the matches."""
    lines: list[str] = []
    at = 0
    for path in ("/.env", "/.git/config", "/backup.sql", "/phpinfo.php"):
        lines.append(line(seconds=at, target=path, status=404, size=0))
        at += 2
    for index in range(30):
        lines.append(line(seconds=at, target=f"/admin/{index}", status=404, size=0))
        at += 1

    result = analyse_ip(build_case(tmp_path, lines).store, ATTACKER)

    assert [episode.category for episode in result.episodes] == [ActivityCategory.ENUMERATION]
    first = result.assignments[0].labelled
    assert first.event.path == "/.env"
    assert "config_file_exposure" in [label.rule_id for label in first.all_labels]


def test_the_graph_is_far_smaller_than_the_log(campaign: Case) -> None:
    """The point of the tool: dozens of requests become a handful of boxes."""
    result = analyse_ip(campaign.store, ATTACKER)

    assert result.request_count > 40
    assert len(result.episodes) < 12


def test_episodes_are_linked_in_the_order_they_happened(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    ids = [node.node_id for node in result.trace.nodes]
    for edge in result.trace.edges:
        assert ids.index(edge.source) < ids.index(edge.target)


def test_a_successful_injection_is_not_reported_as_blocked(campaign: Case) -> None:
    """The difference between an attempt and a breach.

    The refused probes are injection, and blocked. The UNION that came back
    with `username,password FROM users` is the payoff — exploitation since
    2026-10-06 — and must read as having worked.
    """
    result = analyse_ip(campaign.store, ATTACKER)

    probes = [e for e in result.episodes if e.category is ActivityCategory.INJECTION]
    breach = [e for e in result.episodes if e.category is ActivityCategory.EXPLOITATION]
    assert probes
    assert all(episode.outcome is Outcome.BLOCKED for episode in probes)
    assert breach
    assert any(episode.outcome in {Outcome.SUCCESS, Outcome.MIXED} for episode in breach)


def test_every_node_traces_back_to_real_log_lines(campaign: Case) -> None:
    """The forensic requirement: no finding without a line to point at."""
    result = analyse_ip(campaign.store, ATTACKER)
    raw = (campaign.root.parent / "access.log").read_text(encoding="utf-8").splitlines()

    for node in result.trace.nodes:
        assert node.evidence
        for ref in node.evidence:
            assert ref.source_file_id == "access.log"
            assert 1 <= ref.line_no <= len(raw)
            assert ATTACKER in raw[ref.line_no - 1]


def test_reading_a_node_back_returns_the_lines_it_was_built_from(campaign: Case) -> None:
    """Closes the loop the test above leaves open.

    That one checks the references are sound. This one checks the reader the
    CLI and the window both go through resolves them to the same text — a
    correct reference displayed beside the wrong line is worse than no evidence
    panel at all, because it is wrong with a citation attached.
    """
    result = analyse_ip(campaign.store, ATTACKER)
    raw = (campaign.root.parent / "access.log").read_text(encoding="utf-8").splitlines()

    for node in result.trace.nodes:
        for shown in campaign.read_evidence(node.evidence):
            assert shown.available
            assert shown.text == raw[shown.ref.line_no - 1]
            assert shown.text is not None and shown.text.startswith(ATTACKER + " ")


def test_another_client_is_not_mixed_in(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    assert all(episode.client_ip == ATTACKER for episode in result.episodes)


def test_the_behaviour_map_summarises_the_same_evidence(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    assert len(result.behaviour.nodes) <= len(result.trace.nodes)
    assert sum(node.request_count for node in result.behaviour.nodes) == result.request_count


def test_the_result_records_what_produced_it(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    assert len(result.ruleset_fingerprint) == 64
    assert result.policy.as_config()["idle_timeout_seconds"] == 1800


def test_every_request_is_accounted_for_by_exactly_one_episode(campaign: Case) -> None:
    """Nothing is silently dropped between the log and the graph."""
    result = analyse_ip(campaign.store, ATTACKER)
    episode_ids = {episode.episode_id for episode in result.episodes}

    assert len(result.assignments) == result.request_count
    assert all(item.episode_id in episode_ids for item in result.assignments)
    assert sorted(item.evidence.line_no for item in result.assignments) == sorted(
        {item.evidence.line_no for item in result.assignments}
    )


def test_assignments_keep_the_matches_that_lost_the_ranking(campaign: Case) -> None:
    """Which rules matched, not only which one won, so misses can be diagnosed."""
    result = analyse_ip(campaign.store, ATTACKER)

    assert all(item.category in item.categories for item in result.assignments)
    injected = [item for item in result.assignments if item.category is ActivityCategory.INJECTION]
    assert injected
    assert all(item.labelled.all_labels for item in injected)


def test_an_unseen_client_yields_an_empty_reconstruction(campaign: Case) -> None:
    result = analyse_ip(campaign.store, "192.0.2.99")

    assert result.episodes == ()
    assert result.trace.nodes == ()
    assert result.assignments == ()


def test_ordinary_browsing_produces_no_hostile_episodes(tmp_path: Path) -> None:
    lines = [
        line(seconds=n * 30, target=path)
        for n, path in enumerate(
            ["/", "/about", "/products", "/products/1", "/assets/app.css", "/cart", "/checkout"]
        )
    ]
    case = build_case(tmp_path, lines)

    result = analyse_ip(case.store, ATTACKER)

    assert result.hostile_episodes == ()


def test_a_session_break_splits_the_reconstruction(tmp_path: Path) -> None:
    """Two visits hours apart are two stories, not one."""
    lines = [
        line(seconds=0, target="/"),
        line(seconds=10, target="/products"),
        line(seconds=40_000, target="/"),
        line(seconds=40_010, target="/products"),
    ]
    case = build_case(tmp_path, lines)

    result = analyse_ip(case.store, ATTACKER)

    assert len(result.sessions) == 2
    assert result.trace.edges == () or all(
        edge.source.split("/")[0] == edge.target.split("/")[0] for edge in result.trace.edges
    )


# -- reconstructing one stretch of time -------------------------------------


def window_of(case: Case, client: str, keep: int) -> TimeWindow:
    """A window over the first `keep` requests this client made."""
    events = case.store.events_for_ip(client)
    return TimeWindow(events[0].timestamp, events[keep - 1].timestamp)


def test_without_a_window_nothing_about_the_result_changes(campaign: Case) -> None:
    """The contract that keeps every case and report already on disk valid."""
    plain = analyse_ip(campaign.store, ATTACKER)
    open_window = analyse_ip(campaign.store, ATTACKER, window=EVERYTHING)

    assert [n.node_id for n in open_window.trace.nodes] == [n.node_id for n in plain.trace.nodes]
    assert open_window.request_count == plain.request_count


def test_a_window_reconstructs_only_what_happened_inside_it(campaign: Case) -> None:
    """Not a graph with parts hidden — a reconstruction of fewer requests. The
    count on the nodes has to be the count of what is in the window, or an
    activity straddling the edge reports requests that are not there."""
    whole = analyse_ip(campaign.store, ATTACKER)
    window = window_of(campaign, ATTACKER, keep=4)

    narrow = analyse_ip(campaign.store, ATTACKER, window=window)

    assert narrow.request_count == 4
    assert narrow.request_count < whole.request_count
    assert sum(n.request_count for n in narrow.trace.nodes) == 4


def test_a_window_names_every_node_after_itself(campaign: Case) -> None:
    window = window_of(campaign, ATTACKER, keep=4)

    narrow = analyse_ip(campaign.store, ATTACKER, window=window)

    assert narrow.trace.nodes, "premise: something was reconstructed"
    assert all(f"@{window.tag}" in node.node_id for node in narrow.trace.nodes)


def test_two_windows_never_name_a_node_the_same(campaign: Case) -> None:
    """The failure that decided this design: two reports for one client sharing
    an identifier while describing different content."""
    first = analyse_ip(campaign.store, ATTACKER, window=window_of(campaign, ATTACKER, keep=4))
    second = analyse_ip(campaign.store, ATTACKER, window=window_of(campaign, ATTACKER, keep=6))

    assert {n.node_id for n in first.trace.nodes}.isdisjoint(n.node_id for n in second.trace.nodes)


def test_the_result_carries_the_window_it_was_made_with(campaign: Case) -> None:
    """The report has to be able to say what it covers."""
    window = window_of(campaign, ATTACKER, keep=4)

    assert analyse_ip(campaign.store, ATTACKER, window=window).window == window
    assert analyse_ip(campaign.store, ATTACKER).window == EVERYTHING


def test_a_window_holding_nothing_reconstructs_nothing_without_falling_over(
    campaign: Case,
) -> None:
    empty = TimeWindow(datetime(2099, 1, 1, tzinfo=UTC), datetime(2099, 1, 2, tzinfo=UTC))

    result = analyse_ip(campaign.store, ATTACKER, window=empty)

    assert result.episodes == ()
    assert result.trace.nodes == ()


# -- which lines are behind one activity ----------------------------------


def test_a_node_answers_with_the_evidence_of_every_episode_it_holds(
    campaign: Case,
) -> None:
    """Gathered from the episodes the node names, not from `node.evidence`.

    `graphbuild.build` merges a behaviour node's references in episode order
    and cuts them at twenty, so that tuple holds the earliest burst and nothing
    of the latest however long it ran. Read from the episodes instead, the
    panel shows the whole of what the activity did.
    """
    # The sample the window asks for, not the default. `graphbuild.build` cuts a
    # node's merged references at twenty whatever the episodes were given, so at
    # the default sample of twenty the two are the same length and this would
    # pass while proving nothing.
    result = analyse_ip(
        campaign.store,
        ATTACKER,
        policy=AnalysisPolicy(episode=EpisodePolicy(evidence_sample=2_000)),
    )
    biggest = max(result.behaviour.nodes, key=lambda node: node.request_count)

    whole = result.evidence_for(biggest)
    from_the_node = biggest.evidence

    assert len(from_the_node) < len(whole), (
        "premise: the merged tuple is cut and the episodes are not"
    )
    assert set(from_the_node) <= set(whole), "and it is a prefix of the same evidence"


def test_the_evidence_of_an_activity_stops_at_the_ceiling_it_is_given(
    campaign: Case,
) -> None:
    """The reader is waiting while these are read, so there is a limit. Where
    it sits is the caller's business - what belongs here is that it is obeyed.
    """
    result = analyse_ip(campaign.store, ATTACKER)
    biggest = max(result.behaviour.nodes, key=lambda node: node.request_count)

    assert len(result.evidence_for(biggest, limit=3)) == 3


def test_an_activity_whose_episodes_are_gone_answers_with_nothing(
    campaign: Case,
) -> None:
    """Rather than raising. A node naming an episode this result does not hold
    is a graph and a result that disagree, and the panel showing nothing says
    that better than a traceback does.
    """
    result = analyse_ip(campaign.store, ATTACKER)
    stranger = replace(result.trace.nodes[0], episode_ids=("nobody/0",))

    assert result.evidence_for(stranger) == ()
    assert result.requests_for(stranger) == ()


def test_a_node_answers_with_every_request_however_small_its_sample(campaign: Case) -> None:
    """What the evidence filter searches. The sample stops at a ceiling; a match
    past it is still a match, and a filter that missed it would hide evidence."""
    result = analyse_ip(
        campaign.store, ATTACKER, policy=AnalysisPolicy(episode=EpisodePolicy(evidence_sample=5))
    )
    sweep = max(result.trace.nodes, key=lambda node: node.request_count)

    held = result.requests_for(sweep)

    assert len(result.evidence_for(sweep)) == 5, "premise: the sample is cut"
    assert len(held) == sweep.request_count
    times = [item.labelled.event.timestamp for item in held]
    assert times == sorted(times), "in the order the client made them"
    assert {item.episode_id for item in held} <= set(sweep.episode_ids)


def test_every_request_belongs_to_exactly_one_behaviour_node(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    held = [item for node in result.behaviour.nodes for item in result.requests_for(node)]

    assert sorted(item.evidence.line_no for item in held) == sorted(
        item.evidence.line_no for item in result.assignments
    )


@pytest.fixture
def two_logs(tmp_path: Path) -> Case:
    """One sweep, logged across two files, alternating line by line.

    A load balancer in front of two servers writes exactly this, and it is the
    only shape that can tell chronological order apart from file order: with one
    log the two agree, and a test on one log cannot see the difference between
    a right answer and a tidy one.
    """
    first, second = [], []
    for index in range(20):
        target = f"/admin/{index}"
        (first if index % 2 == 0 else second).append(
            line(seconds=index, target=target, status=404, size=0)
        )

    left, right = tmp_path / "a.log", tmp_path / "b.log"
    left.write_text("\n".join(first) + "\n", encoding="utf-8")
    right.write_text("\n".join(second) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([left, right])
    return Case.open(tmp_path / "case")


def test_the_lines_come_back_as_performed_not_sorted_by_file(two_logs: Case) -> None:
    """Chronological, because the episodes are, and deliberately not by file.

    Sorted by source and line number, a reader would be shown one server's whole
    story and then the other's, rather than the sequence the client actually
    performed. On a forensic tool the order *is* part of the evidence.
    """
    result = analyse_ip(two_logs.store, ATTACKER)
    biggest = max(result.trace.nodes, key=lambda node: node.request_count)

    refs = result.evidence_for(biggest)
    sources = [ref.source_file_id for ref in refs]

    assert len(set(sources)) == 2, "premise: this activity spans both logs"
    assert sources != sorted(sources), "premise: file order is not the order performed"
    assert sources == ["a.log", "b.log"] * (len(sources) // 2), "the sweep is interleaved"


def test_a_report_says_which_domains_it_was_told_were_yours(campaign: Case) -> None:
    """**Provenance for a finding that rests on a person's answer, not on the log.**

    `rfi_offsite_url` calls a URL hostile because it points at a host nobody
    named as this site's. Every other rule in the tree is checkable from the
    evidence line alone; this one is only checkable if the report also says what
    it was comparing against.

    It matters most when the answer is wrong. A reader who mistypes their own
    domain turns every ordinary outbound link into a finding, and without this
    field the report gives them no way to see why.
    """
    engine = RuleEngine(default_rules(), site_hosts=("Shop.Example.COM:443",))

    result = analyse_ip(campaign.store, ATTACKER, engine=engine)

    # Reduced the same way the comparison reduces them, so the report shows
    # what was actually used rather than what was typed.
    assert result.site_hosts == ("shop.example.com",)
    assert result.to_dict()["site_hosts"] == ["shop.example.com"]


def test_a_report_with_no_answer_says_so_rather_than_omitting_it(campaign: Case) -> None:
    """An empty list, present. A reader comparing two reports should be able to
    see that one was answered and the other was not, and a missing key reads as
    an older report rather than as an unanswered question."""
    result = analyse_ip(campaign.store, ATTACKER)

    assert result.site_hosts == ()
    assert result.to_dict()["site_hosts"] == []


def test_an_export_names_the_version_that_analysed_it(campaign: Case) -> None:
    """Not the case's `tool_version`, which is the version that created it: a
    case outlives the release it was read with."""
    from logarc import __version__

    payload = analyse_ip(campaign.store, ATTACKER).to_dict()

    assert payload["analysed_with"] == __version__
