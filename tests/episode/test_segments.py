"""Episodes together with the requests that went into them.

Scoring segmentation, and showing the evidence behind a graph node, both need
to know which requests ended up in which episode. That mapping exists while the
episodes are being built and used to be thrown away.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from zodiarc.core.activity import ActivityCategory, ActivityLabel, Severity
from zodiarc.core.event import NormalizedEvent
from zodiarc.core.evidence import EvidenceRef
from zodiarc.detect.engine import LabelledEvent
from zodiarc.episode.builder import build_episodes, segment

START = datetime(2024, 5, 1, 9, 0, tzinfo=UTC)


def label(category: ActivityCategory) -> ActivityLabel:
    return ActivityLabel(
        rule_id=f"test:{category.value}",
        name=category.value.title(),
        category=category,
        severity=Severity.HIGH if category.is_hostile else Severity.INFO,
        confidence=0.9,
    )


def request(offset: int, category: ActivityCategory, line_no: int) -> LabelledEvent:
    return LabelledEvent(
        event=NormalizedEvent(
            timestamp=START + timedelta(seconds=offset),
            client_ip="100.67.0.1",
            path=f"/page-{line_no}",
            status=200,
            evidence=EvidenceRef("access.log", line_no),
        ),
        label=label(category),
    )


def test_every_request_belongs_to_exactly_one_episode() -> None:
    labelled = [
        request(0, ActivityCategory.BROWSING, 1),
        request(10, ActivityCategory.BROWSING, 2),
        request(20, ActivityCategory.INJECTION, 3),
        request(30, ActivityCategory.INJECTION, 4),
    ]

    segments = segment(labelled, session_id="s1")

    assigned = [item.event.evidence.line_no for part in segments for item in part.members]
    assert assigned == [1, 2, 3, 4]
    assert [part.episode.request_count for part in segments] == [2, 2]


def test_members_survive_noise_absorption() -> None:
    """The absorbed interlude belongs to the episode that swallowed it."""
    labelled = [
        request(0, ActivityCategory.INJECTION, 1),
        request(5, ActivityCategory.STATIC_ASSET, 2),
        request(10, ActivityCategory.INJECTION, 3),
    ]

    segments = segment(labelled, session_id="s1")

    assert len(segments) == 1
    assert [item.event.evidence.line_no for item in segments[0].members] == [1, 2, 3]
    assert segments[0].episode.request_count == 3


def test_the_episode_ids_are_the_ones_the_episodes_carry() -> None:
    labelled = [
        request(0, ActivityCategory.BROWSING, 1),
        request(20, ActivityCategory.INJECTION, 2),
    ]

    segments = segment(labelled, session_id="s7")

    assert [part.episode.episode_id for part in segments] == ["s7/1", "s7/2"]


def test_building_episodes_is_the_same_segmentation_without_the_members() -> None:
    labelled = [
        request(0, ActivityCategory.BROWSING, 1),
        request(20, ActivityCategory.INJECTION, 2),
        request(25, ActivityCategory.INJECTION, 3),
    ]

    assert build_episodes(labelled, session_id="s1") == [
        part.episode for part in segment(labelled, session_id="s1")
    ]


def test_segmenting_nothing_produces_nothing() -> None:
    assert segment([], session_id="s1") == []
