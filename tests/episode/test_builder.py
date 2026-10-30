"""Tests for merging labelled requests into activity episodes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from zodiarc.core.activity import ActivityCategory, ActivityLabel, Outcome, Severity
from zodiarc.core.event import NormalizedEvent
from zodiarc.core.evidence import EvidenceRef
from zodiarc.detect.engine import LabelledEvent
from zodiarc.episode.builder import EpisodePolicy, build_episodes

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def label(
    category: ActivityCategory,
    *,
    rule_id: str = "rule",
    severity: Severity = Severity.MEDIUM,
) -> ActivityLabel:
    return ActivityLabel(
        rule_id=rule_id,
        name=rule_id,
        category=category,
        severity=severity,
        confidence=0.9,
    )


def labelled(
    category: ActivityCategory,
    *,
    seconds: float = 0,
    path: str = "/a",
    status: int | None = 200,
    bytes_sent: int = 100,
    severity: Severity = Severity.MEDIUM,
    rule_id: str = "rule",
    referer: str | None = None,
) -> LabelledEvent:
    event = NormalizedEvent(
        timestamp=START + timedelta(seconds=seconds),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", int(seconds) + 1),
        method="GET",
        path=path,
        status=status,
        bytes_sent=bytes_sent,
        referer=referer,
    )
    activity = label(category, rule_id=rule_id, severity=severity)
    return LabelledEvent(event=event, label=activity, all_labels=[activity])


def test_no_events_produce_no_episodes() -> None:
    assert build_episodes([]) == []


def test_consecutive_requests_of_one_category_form_one_episode() -> None:
    events = [labelled(ActivityCategory.INJECTION, seconds=n) for n in range(5)]

    (episode,) = build_episodes(events)

    assert episode.request_count == 5
    assert episode.activity.category is ActivityCategory.INJECTION


def test_a_change_of_category_starts_a_new_episode() -> None:
    events = [
        labelled(ActivityCategory.RECONNAISSANCE, seconds=0),
        labelled(ActivityCategory.INJECTION, seconds=1),
    ]

    episodes = build_episodes(events)

    assert [e.activity.category for e in episodes] == [
        ActivityCategory.RECONNAISSANCE,
        ActivityCategory.INJECTION,
    ]


def test_a_long_gap_splits_an_episode_even_within_one_category() -> None:
    """The same activity resumed an hour later is a separate act."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        labelled(ActivityCategory.INJECTION, seconds=3600),
    ]

    assert len(build_episodes(events)) == 2


def test_a_gap_exactly_at_the_threshold_does_not_split() -> None:
    policy = EpisodePolicy(max_gap=timedelta(minutes=5))
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        labelled(ActivityCategory.INJECTION, seconds=300),
    ]

    assert len(build_episodes(events, policy=policy)) == 1


def test_a_page_and_its_sub_resources_are_one_episode() -> None:
    """The fix for the shape of the whole output.

    A page load is one act: the document, the stylesheets and images it pulls
    in, and the XHR it fires. Cutting an episode at each of those transitions
    made 58.5% of episodes a single request on one measured corpus — 10,196
    episodes against 2,475 real activities — and a graph that should read as a
    sentence read as confetti.
    """
    events = [
        labelled(ActivityCategory.BROWSING, seconds=0, path="/products", severity=Severity.INFO),
        *[
            labelled(
                ActivityCategory.STATIC_ASSET,
                seconds=n * 0.1,
                path=f"/assets/{n}.css",
                severity=Severity.INFO,
            )
            for n in range(1, 9)
        ],
        labelled(ActivityCategory.API_CALL, seconds=1, path="/api/cart", severity=Severity.INFO),
    ]

    (episode,) = build_episodes(events)

    assert episode.request_count == 10


def test_a_merged_group_is_named_for_the_page_not_the_assets() -> None:
    """Severity and confidence tie across benign labels, so without an explicit
    order the name falls to whichever request happened to arrive first — "Static
    Asset" whenever the images beat the document."""
    events = [
        *[
            labelled(
                ActivityCategory.STATIC_ASSET,
                seconds=n * 0.1,
                path=f"/assets/{n}.png",
                severity=Severity.INFO,
            )
            for n in range(6)
        ],
        labelled(ActivityCategory.BROWSING, seconds=1, path="/products", severity=Severity.INFO),
    ]

    (episode,) = build_episodes(events)

    assert episode.activity.category is ActivityCategory.BROWSING


def test_an_attack_amid_ordinary_use_still_keeps_its_own_episode() -> None:
    """The invariant the merge must not break: grouping sub-resources together
    must not also swallow the attack sitting between two page loads."""
    events = [
        labelled(ActivityCategory.BROWSING, seconds=0, severity=Severity.INFO),
        labelled(ActivityCategory.STATIC_ASSET, seconds=1, severity=Severity.INFO),
        labelled(ActivityCategory.INJECTION, seconds=2),
        labelled(ActivityCategory.BROWSING, seconds=3, severity=Severity.INFO),
        labelled(ActivityCategory.STATIC_ASSET, seconds=4, severity=Severity.INFO),
    ]

    episodes = build_episodes(events)

    assert [e.activity.category for e in episodes] == [
        ActivityCategory.BROWSING,
        ActivityCategory.INJECTION,
        ActivityCategory.BROWSING,
    ]


def test_signing_in_is_still_its_own_step() -> None:
    """Ordinary use is grouped; authenticating is not part of it.

    An analyst reading a trace wants to see "browsed, signed in, browsed" — the
    moment the client became someone is the thing the trace is for.
    """
    events = [
        *[labelled(ActivityCategory.BROWSING, seconds=n, severity=Severity.INFO) for n in range(2)],
        *[
            labelled(
                ActivityCategory.AUTHENTICATION, seconds=n, path="/login", severity=Severity.INFO
            )
            for n in range(2, 7)
        ],
        *[
            labelled(ActivityCategory.BROWSING, seconds=n, severity=Severity.INFO)
            for n in range(7, 9)
        ],
    ]

    episodes = build_episodes(events)

    assert [e.activity.category for e in episodes] == [
        ActivityCategory.BROWSING,
        ActivityCategory.AUTHENTICATION,
        ActivityCategory.BROWSING,
    ]


def _files(seconds: float, referer: str | None, count: int = 5) -> list[LabelledEvent]:
    return [
        labelled(
            ActivityCategory.STATIC_ASSET,
            seconds=seconds + n * 0.1,
            path=f"/assets/{n}.css",
            severity=Severity.INFO,
            referer=referer,
        )
        for n in range(count)
    ]


def test_a_sign_in_page_keeps_the_files_it_loaded() -> None:
    """The stylesheets a sign-in page pulls in are part of loading it, as their
    Referer says. Cut away as ordinary use, five of them were too many to be
    absorbed, and one sign-in became three episodes."""
    events = [
        labelled(ActivityCategory.AUTHENTICATION, seconds=0, path="/login", severity=Severity.INFO),
        *_files(1, "https://shop.test/login?next=%2Fadmin"),
        labelled(ActivityCategory.AUTHENTICATION, seconds=4, path="/login", severity=Severity.INFO),
    ]

    (episode,) = build_episodes(events)

    assert episode.request_count == 7
    assert episode.activity.category is ActivityCategory.AUTHENTICATION


def test_a_file_the_page_did_not_load_is_not_claimed() -> None:
    """The next page's images can arrive before its document. Without a Referer
    naming the sign-in page, they belong to what follows, as before."""
    for referer in (None, "https://shop.test/p/1"):
        events = [
            labelled(
                ActivityCategory.AUTHENTICATION, seconds=0, path="/login", severity=Severity.INFO
            ),
            *_files(1, referer),
            labelled(ActivityCategory.BROWSING, seconds=2, path="/p/1", severity=Severity.INFO),
        ]

        episodes = build_episodes(events)

        assert [e.request_count for e in episodes] == [1, 6], referer


def test_a_file_after_an_attack_is_still_its_own_step() -> None:
    """An attack's request keeps its own episode, whatever fetched what."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, path="/search"),
        *_files(1, "https://shop.test/search"),
    ]

    episodes = build_episodes(events)

    assert [e.activity.category for e in episodes] == [
        ActivityCategory.INJECTION,
        ActivityCategory.STATIC_ASSET,
    ]


def test_a_gap_still_splits_grouped_ordinary_use() -> None:
    """Grouping is about category, not about time. An hour later is a new act."""
    events = [
        labelled(ActivityCategory.BROWSING, seconds=0, severity=Severity.INFO),
        labelled(ActivityCategory.STATIC_ASSET, seconds=1, severity=Severity.INFO),
        labelled(ActivityCategory.STATIC_ASSET, seconds=3600, severity=Severity.INFO),
        labelled(ActivityCategory.BROWSING, seconds=3601, severity=Severity.INFO),
    ]

    assert len(build_episodes(events)) == 2


def test_a_benign_label_never_names_an_episode_over_a_hostile_one() -> None:
    """Regression from adding the benign naming order.

    That order breaks ties between benign labels, which all sit at one severity
    and one confidence. Applied without qualification it also broke the tie
    between a benign label and a hostile one that happened to match on both, and
    handed an injection episode the name "Static Asset". An episode is named for
    the worst thing in it; nothing about grouping page loads changes that.
    """
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, severity=Severity.MEDIUM),
        labelled(ActivityCategory.STATIC_ASSET, seconds=1, severity=Severity.MEDIUM),
    ]

    episodes = build_episodes(events)

    assert [e.activity.category for e in episodes] == [
        ActivityCategory.INJECTION,
        ActivityCategory.STATIC_ASSET,
    ]


def test_a_short_benign_interlude_is_absorbed() -> None:
    """Without this, one favicon fetch mid-attack splits a single episode into
    three and the graph turns into fragments."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        labelled(ActivityCategory.INJECTION, seconds=1),
        labelled(ActivityCategory.STATIC_ASSET, seconds=2, path="/favicon.ico"),
        labelled(ActivityCategory.INJECTION, seconds=3),
        labelled(ActivityCategory.INJECTION, seconds=4),
    ]

    (episode,) = build_episodes(events)

    assert episode.activity.category is ActivityCategory.INJECTION
    assert episode.request_count == 5


def test_a_substantial_benign_stretch_is_not_absorbed() -> None:
    """Real browsing between two attacks is part of the story, not noise."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        *[labelled(ActivityCategory.BROWSING, seconds=n) for n in range(1, 9)],
        labelled(ActivityCategory.INJECTION, seconds=10),
    ]

    assert len(build_episodes(events)) == 3


def test_a_slow_benign_interlude_is_not_absorbed() -> None:
    """Few requests but spread over minutes is a pause, not noise."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        labelled(ActivityCategory.STATIC_ASSET, seconds=100, path="/x.css"),
        labelled(ActivityCategory.INJECTION, seconds=200),
    ]

    assert len(build_episodes(events)) == 3


def test_an_interlude_between_different_categories_is_not_absorbed() -> None:
    events = [
        labelled(ActivityCategory.RECONNAISSANCE, seconds=0),
        labelled(ActivityCategory.STATIC_ASSET, seconds=1),
        labelled(ActivityCategory.INJECTION, seconds=2),
    ]

    assert len(build_episodes(events)) == 3


def test_a_hostile_interlude_is_never_absorbed() -> None:
    """Only benign noise is absorbed; an attack between two attacks is a step."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        labelled(ActivityCategory.SSRF, seconds=1),
        labelled(ActivityCategory.INJECTION, seconds=2),
    ]

    assert len(build_episodes(events)) == 3


def test_absorption_can_be_turned_off() -> None:
    policy = EpisodePolicy(absorb_noise=False)
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0),
        labelled(ActivityCategory.STATIC_ASSET, seconds=1),
        labelled(ActivityCategory.INJECTION, seconds=2),
    ]

    assert len(build_episodes(events, policy=policy)) == 3


def test_an_episode_reports_its_span_and_shape() -> None:
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, path="/a", bytes_sent=10),
        labelled(ActivityCategory.INJECTION, seconds=30, path="/b", bytes_sent=20),
        labelled(ActivityCategory.INJECTION, seconds=60, path="/a", bytes_sent=30),
    ]

    (episode,) = build_episodes(events)

    assert episode.start == START
    assert episode.end == START + timedelta(seconds=60)
    assert episode.duration == timedelta(seconds=60)
    assert episode.request_count == 3
    assert episode.distinct_paths == 2
    assert episode.bytes_total == 60


def test_the_most_severe_label_represents_the_episode() -> None:
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, severity=Severity.LOW, rule_id="mild"),
        labelled(ActivityCategory.INJECTION, seconds=1, severity=Severity.CRITICAL, rule_id="bad"),
    ]

    (episode,) = build_episodes(events)

    assert episode.activity.rule_id == "bad"
    assert episode.severity is Severity.CRITICAL


def test_every_rule_that_fired_is_listed() -> None:
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, rule_id="sqli"),
        labelled(ActivityCategory.INJECTION, seconds=1, rule_id="xss"),
    ]

    (episode,) = build_episodes(events)

    assert set(episode.rule_ids) == {"sqli", "xss"}


def test_an_episode_where_nothing_succeeded_is_blocked() -> None:
    events = [labelled(ActivityCategory.INJECTION, seconds=n, status=403) for n in range(3)]

    (episode,) = build_episodes(events)

    assert episode.outcome is Outcome.BLOCKED


def test_an_episode_where_everything_succeeded_is_a_success() -> None:
    events = [labelled(ActivityCategory.INJECTION, seconds=n, status=200) for n in range(3)]

    (episode,) = build_episodes(events)

    assert episode.outcome is Outcome.SUCCESS


def test_an_episode_with_some_successes_is_mixed() -> None:
    """This is the distinction that matters most: attempts that were refused
    versus attempts that got through."""
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, status=403),
        labelled(ActivityCategory.INJECTION, seconds=1, status=200),
    ]

    (episode,) = build_episodes(events)

    assert episode.outcome is Outcome.MIXED


def test_an_episode_without_status_codes_has_an_unknown_outcome() -> None:
    events = [labelled(ActivityCategory.INJECTION, seconds=0, status=None)]

    (episode,) = build_episodes(events)

    assert episode.outcome is Outcome.UNKNOWN


def test_the_status_histogram_is_kept() -> None:
    events = [
        labelled(ActivityCategory.INJECTION, seconds=0, status=403),
        labelled(ActivityCategory.INJECTION, seconds=1, status=403),
        labelled(ActivityCategory.INJECTION, seconds=2, status=200),
    ]

    (episode,) = build_episodes(events)

    assert dict(episode.status_histogram) == {403: 2, 200: 1}


def test_the_busiest_targets_are_listed() -> None:
    events = [
        *[labelled(ActivityCategory.INJECTION, seconds=n, path="/hot") for n in range(3)],
        labelled(ActivityCategory.INJECTION, seconds=4, path="/cold"),
    ]

    (episode,) = build_episodes(events)

    assert episode.top_targets[0] == "/hot"


def test_evidence_points_back_at_the_raw_log_lines() -> None:
    events = [labelled(ActivityCategory.INJECTION, seconds=n) for n in range(3)]

    (episode,) = build_episodes(events)

    assert episode.evidence[0] == EvidenceRef("access.log", 1)
    assert episode.evidence_total == 3


def test_evidence_is_sampled_but_the_true_count_is_kept() -> None:
    """A thousand-request episode must not carry a thousand references, but a
    report still has to state how many there were."""
    policy = EpisodePolicy(evidence_sample=5)
    events = [labelled(ActivityCategory.INJECTION, seconds=n) for n in range(50)]

    (episode,) = build_episodes(events, policy=policy)

    assert len(episode.evidence) == 5
    assert episode.evidence_total == 50


def test_episode_ids_are_stable_and_ordered() -> None:
    events = [
        labelled(ActivityCategory.RECONNAISSANCE, seconds=0),
        labelled(ActivityCategory.INJECTION, seconds=1),
    ]

    episodes = build_episodes(events, session_id="203.0.113.5#1")

    assert [e.episode_id for e in episodes] == ["203.0.113.5#1/1", "203.0.113.5#1/2"]
