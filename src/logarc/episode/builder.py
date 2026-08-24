"""Level 3 segmentation: turning labelled requests into episodes.

This is the step that answers "where does one action end and the next begin".
Two passes, both linear:

1. **Split.** Start a new episode when the activity category changes, or when
   the gap since the previous request exceeds a threshold. The same activity
   resumed an hour later is a separate act.

2. **Absorb.** Merge two same-category episodes separated by a *short* run of
   benign requests, taking the interlude with them.

The second pass is the one non-obvious rule in the whole design, and it is
load-bearing. Without it a single `favicon.ico` fetch in the middle of an attack
splits one episode into three, and a graph that should read as a sentence reads
as confetti. It is stated explicitly rather than buried so that its effect on
results can be argued about and measured.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

from logarc.core.activity import ActivityCategory
from logarc.core.episode import Episode, derive_outcome
from logarc.normalize.decode import canonical_path

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.activity import ActivityLabel
    from logarc.detect.engine import LabelledEvent

__all__ = ["EpisodePolicy", "EpisodeSegment", "build_episodes", "segment"]

#: Same activity, but this far apart, is a separate act rather than a pause.
DEFAULT_MAX_GAP: Final = timedelta(minutes=5)

#: An interlude longer than this is real behaviour, not noise between steps.
DEFAULT_ABSORB_MAX_REQUESTS: Final = 3
DEFAULT_ABSORB_MAX_DURATION: Final = timedelta(seconds=60)

#: Source references kept per episode. Enough to substantiate a finding without
#: carrying the whole log around.
DEFAULT_EVIDENCE_SAMPLE: Final = 20

#: Distinct targets named on a graph node before it becomes unreadable.
_TOP_TARGETS: Final = 5

#: Categories that are one act rather than three, for the purpose of cutting.
#:
#: Fetching a page, the stylesheets and images it pulls in, and the XHR it
#: fires are not three activities a reader wants three nodes for — they are one
#: page load. Splitting on the raw category made 58.5% of episodes a single
#: request on a measured corpus, because `browsing -> static_asset ->
#: api_call -> browsing` is what every ordinary page looks like; those three
#: transitions alone were 11,777 of roughly 13,000 boundaries.
#:
#: `_absorb_noise` cannot reach this. It merges runs of the *same* category
#: separated by a brief interlude, and here every run is a different category.
#:
#: Deliberately narrow. `authentication` is left out: signing in is the moment a
#: client becomes someone, and a trace that reads "browsed, signed in, browsed"
#: is the point of having a trace. `crawling` is left out because a crawler is
#: recognised by its user-agent, so all of its requests already carry that one
#: category and never interleave. Every hostile category keeps its own class, so
#: an attack between two page loads still gets its own node.
_ORDINARY_USE: Final[frozenset[ActivityCategory]] = frozenset(
    {
        ActivityCategory.BROWSING,
        ActivityCategory.STATIC_ASSET,
        ActivityCategory.API_CALL,
    }
)

#: Which benign label names an episode that contains several.
#:
#: Benign labels are all INFO at one confidence, so they tie, and `max` returns
#: whichever arrived first — a page load whose images beat the document came out
#: called "Static Asset". Ordered most-worth-naming first; anything absent
#: (every hostile category) ranks below all of them and never needs to, because
#: severity has already decided by then.
_NAMING_ORDER: Final[tuple[ActivityCategory, ...]] = (
    ActivityCategory.BROWSING,
    ActivityCategory.AUTHENTICATION,
    ActivityCategory.API_CALL,
    ActivityCategory.STATIC_ASSET,
    ActivityCategory.CRAWLING,
)


def _boundary_class(category: ActivityCategory) -> str:
    """What a category counts as when deciding where one act ends.

    Coarser than the category itself, and used for nothing else: the episode is
    still labelled, reported and scored by its real category.
    """
    return "ordinary_use" if category in _ORDINARY_USE else category.value


def _naming_rank(category: ActivityCategory) -> int:
    """Higher names the episode where severity and confidence tie."""
    if category not in _NAMING_ORDER:
        return 0
    return len(_NAMING_ORDER) - _NAMING_ORDER.index(category)


@dataclass(frozen=True, slots=True)
class EpisodePolicy:
    """The thresholds an episode segmentation was run with."""

    max_gap: timedelta = DEFAULT_MAX_GAP
    absorb_noise: bool = True
    absorb_max_requests: int = DEFAULT_ABSORB_MAX_REQUESTS
    absorb_max_duration: timedelta = DEFAULT_ABSORB_MAX_DURATION
    evidence_sample: int = DEFAULT_EVIDENCE_SAMPLE

    def as_config(self) -> dict[str, object]:
        """The form recorded in the case manifest."""
        return {
            "episode_max_gap_seconds": int(self.max_gap.total_seconds()),
            "absorb_noise": self.absorb_noise,
            "absorb_max_requests": self.absorb_max_requests,
            "absorb_max_duration_seconds": int(self.absorb_max_duration.total_seconds()),
            "evidence_sample": self.evidence_sample,
        }


@dataclass(frozen=True, slots=True)
class EpisodeSegment:
    """An episode and the requests that went into it.

    The membership exists while an episode is being built and used to be
    discarded. Two things need it: scoring where the boundaries were put, and
    showing an investigator the raw lines behind a node they clicked on.
    """

    episode: Episode
    members: tuple[LabelledEvent, ...]


def build_episodes(
    labelled: Sequence[LabelledEvent],
    *,
    session_id: str = "",
    policy: EpisodePolicy | None = None,
) -> list[Episode]:
    """Group labelled requests into episodes."""
    return [part.episode for part in segment(labelled, session_id=session_id, policy=policy)]


def segment(
    labelled: Sequence[LabelledEvent],
    *,
    session_id: str = "",
    policy: EpisodePolicy | None = None,
) -> list[EpisodeSegment]:
    """Group labelled requests into episodes, keeping what went into each."""
    policy = policy or EpisodePolicy()
    if not labelled:
        return []

    runs = _split(labelled, policy)
    if policy.absorb_noise:
        runs = _absorb_noise(runs, policy)

    return [
        EpisodeSegment(
            episode=_build(run, session_id=session_id, index=index, policy=policy),
            members=tuple(run),
        )
        for index, run in enumerate(runs, start=1)
    ]


def _split(labelled: Sequence[LabelledEvent], policy: EpisodePolicy) -> list[list[LabelledEvent]]:
    runs: list[list[LabelledEvent]] = []
    current: list[LabelledEvent] = []

    for item in labelled:
        if current and _is_boundary(current[-1], item, policy):
            runs.append(current)
            current = []
        current.append(item)

    if current:
        runs.append(current)
    return runs


def _is_boundary(previous: LabelledEvent, item: LabelledEvent, policy: EpisodePolicy) -> bool:
    if _boundary_class(previous.label.category) != _boundary_class(item.label.category):
        return True
    gap = item.event.timestamp - previous.event.timestamp
    return gap > policy.max_gap


def _absorb_noise(
    runs: list[list[LabelledEvent]], policy: EpisodePolicy
) -> list[list[LabelledEvent]]:
    """Rejoin same-category runs split only by a brief benign interlude."""
    merged: list[list[LabelledEvent]] = []
    index = 0

    while index < len(runs):
        run = runs[index]
        # Look for the pattern: this run, a short benign run, a run of the same
        # category as this one. Repeated, so several interruptions collapse too.
        while index + 2 < len(runs) and _is_absorbable(
            run, runs[index + 1], runs[index + 2], policy
        ):
            run = [*run, *runs[index + 1], *runs[index + 2]]
            index += 2
        merged.append(run)
        index += 1

    return merged


def _is_absorbable(
    before: Sequence[LabelledEvent],
    interlude: Sequence[LabelledEvent],
    after: Sequence[LabelledEvent],
    policy: EpisodePolicy,
) -> bool:
    if before[-1].label.category is not after[0].label.category:
        return False

    # Only benign traffic is noise. An attack between two attacks is a step in
    # the sequence and must keep its own node.
    if any(item.label.category.is_hostile for item in interlude):
        return False

    if len(interlude) > policy.absorb_max_requests:
        return False

    span = after[0].event.timestamp - before[-1].event.timestamp
    return span <= policy.absorb_max_duration


def _build(
    run: Sequence[LabelledEvent],
    *,
    session_id: str,
    index: int,
    policy: EpisodePolicy,
) -> Episode:
    events = [item.event for item in run]
    statuses = [event.status for event in events]

    # Counted canonically, displayed raw. `/a/b` and `/a//b` are one resource
    # and must count once, but an analyst reading `top_targets` should see what
    # was actually requested rather than a tidied version of it.
    targets = Counter(event.path for event in events if event.path)
    distinct = {canonical_path(event.path) for event in events if event.path}
    histogram = Counter(status for status in statuses if status is not None)

    return Episode(
        episode_id=f"{session_id}/{index}" if session_id else str(index),
        session_id=session_id,
        client_ip=events[0].client_ip,
        activity=_representative(run),
        start=events[0].timestamp,
        end=events[-1].timestamp,
        request_count=len(events),
        distinct_paths=len(distinct),
        bytes_total=sum(event.bytes_sent or 0 for event in events),
        status_histogram=dict(histogram),
        top_targets=tuple(path for path, _ in targets.most_common(_TOP_TARGETS)),
        rule_ids=tuple(sorted({item.label.rule_id for item in run})),
        outcome=derive_outcome(statuses),
        evidence=tuple(event.evidence for event in events[: policy.evidence_sample]),
        evidence_total=len(events),
    )


def _representative(run: Sequence[LabelledEvent]) -> ActivityLabel:
    """The label the episode is named after: the worst thing that happened in it."""
    return max(
        (item.label for item in run),
        key=lambda activity: (
            activity.severity,
            activity.confidence,
            # Before the benign order, so a benign label can never name an
            # episode over a hostile one that merely happens to tie with it.
            activity.category.is_hostile,
            _naming_rank(activity.category),
        ),
    )
