"""End-to-end tests for the reconstruction pipeline.

These drive the whole engine — parse, store, sessionize, label, segment,
graph — against logs written to look like real attacker behaviour. If the story
these produce is wrong, the tool is wrong regardless of what the unit tests say.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.activity import ActivityCategory, Outcome

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
    """The difference between an attempt and a breach."""
    result = analyse_ip(campaign.store, ATTACKER)

    injection = [e for e in result.episodes if e.category is ActivityCategory.INJECTION]
    assert injection
    assert any(episode.outcome in {Outcome.SUCCESS, Outcome.MIXED} for episode in injection)


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


def test_an_unseen_client_yields_an_empty_reconstruction(campaign: Case) -> None:
    result = analyse_ip(campaign.store, "192.0.2.99")

    assert result.episodes == ()
    assert result.trace.nodes == ()


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
