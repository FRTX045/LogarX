"""What a Suspicious activity recommendation says, reason by reason.

Each reason answers three questions: what was observed (`text`), why that deserves
attention (`why`), and which requests to inspect (`examples`, or `evidence` where no
request can be named). The wording claims no more than the counts show: a
high-confidence rule match is not a confirmed attack, an ordering in one session is
not one actor's plan, and recurrence across sessions is not persistence.

The `why` of the single-match, recurrence and support reasons are drafts, to be
settled at the review of the recommendation preview.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from logarc.core.activity import Severity
from logarc.triage.profile import SAMPLE_SIZE, PriorityReason

if TYPE_CHECKING:
    from logarc.triage.profile import ClientProfile


def suspicious_reasons(profile: ClientProfile) -> tuple[PriorityReason, ...]:
    """Reasons in a fixed order, leaving out any that do not apply to this client.

    Distinct high-confidence matches, then a probe followed by an attack pattern,
    then recurrence across sessions, then support, share and severity, which apply
    to every client in the queue, then the per-category reasons profiling wrote.
    """
    reasons = [
        reason
        for reason in (_distinct(profile), _sequence(profile), _recurrence(profile))
        if reason is not None
    ]
    return (*reasons, _support(profile), *profile.reasons)


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count:,} {word if count == 1 else plural or word + 's'}"


def _distinct(profile: ClientProfile) -> PriorityReason | None:
    pairs = profile.distinct_rule_pairs
    if not pairs:
        return None
    return PriorityReason(
        f"{_plural(pairs, 'rule')} matched on {_plural(pairs, 'request')}.",
        tuple(example.evidence for example in profile.distinct_examples),
        kind="distinct_rules",
        why=(
            "Distinct high-confidence rule matches provide support beyond repetition of one rule."
            if pairs > 1
            else "One high-confidence rule match: a narrowly defined pattern, seen once."
        ),
        summary=_plural(pairs, "high-confidence rule match", "high-confidence rule matches"),
        examples=profile.distinct_examples,
    )


def _sequence(profile: ClientProfile) -> PriorityReason | None:
    sessions = profile.sequence_sessions
    if not sessions or len(profile.sequence_examples) != 2:
        return None
    probe, attack = profile.sequence_examples
    text = (
        f"{probe.note} was followed by an attack-pattern match ({attack.note}) "
        f"against {attack.path or 'an unrecorded path'} in the same session."
    )
    if sessions > 1:
        text += f" The same ordering occurs in {sessions:,} sessions."
    return PriorityReason(
        text,
        (probe.evidence, attack.evidence),
        kind="sequence",
        why="The ordering makes this session worth reviewing as a whole.",
        summary=f"{probe.note} then {attack.note}, {_plural(sessions, 'session')}",
        examples=profile.sequence_examples,
    )


def _span(first: str, last: str) -> str:
    """Whole units, rounded down: minutes under an hour, hours under two days, else days."""
    seconds = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds()
    if seconds < 60:
        return "less than a minute"
    if seconds < 3600:
        return _plural(int(seconds // 60), "minute")
    if seconds < 48 * 3600:
        return _plural(int(seconds // 3600), "hour")
    return _plural(int(seconds // 86400), "day")


def _recurrence(profile: ClientProfile) -> PriorityReason | None:
    hostile, sessions = profile.hostile_sessions, profile.sessions
    if hostile < 2 or profile.first_hostile is None or profile.last_hostile is None:
        return None
    return PriorityReason(
        f"Hostile detections occurred in {hostile:,} of {sessions:,} sessions. "
        "The first and last matching requests were "
        f"{_span(profile.first_hostile, profile.last_hostile)} apart.",
        tuple(example.evidence for example in profile.recurrence_examples),
        kind="recurrence",
        why="Detections recur in separate sessions rather than in one isolated burst.",
        summary=f"Hostile in {hostile:,} of {sessions:,} sessions",
        examples=profile.recurrence_examples,
    )


def _support(profile: ClientProfile) -> PriorityReason:
    hostile, requests = profile.hostile_requests, profile.requests
    severity = Severity(profile.severity).name.lower()
    return PriorityReason(
        f"{hostile:,} of {requests:,} requests have hostile detections "
        f"({hostile / requests:.0%}); strongest severity {severity}.",
        tuple(dict.fromkeys(ref for reason in profile.reasons for ref in reason.evidence))[
            :SAMPLE_SIZE
        ],
        kind="support",
        why=(
            "Repeated hostile detections distinguish a pattern from an isolated match."
            if hostile > 1
            else "A single hostile detection: inspect it before relying on it."
        ),
        summary=f"{hostile:,} of {requests:,} requests hostile; strongest {severity}",
    )
