"""What a Suspicious activity recommendation says, reason by reason.

Each reason answers three questions: what was observed (`text`), why that
observation deserves attention for this client (`why`), and which requests to
inspect (`examples`, or `evidence` where no request can be named). The flagged
requests come first because they are what the queue's order rests on; the other
reasons are context for reading the client, not the source of its rank.

The wording claims no more than the counts show: a rule's author-assigned rating
describes the rule, not the request; an ordering in one session is not one actor's
plan; and detections in several sessions are not persistence.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from logarc.core.activity import Severity
from logarc.triage.profile import SAMPLE_SIZE, PriorityReason

if TYPE_CHECKING:
    from logarc.triage.profile import ClientProfile

#: How a category reads inside "Flagged requests, mostly ...".
KINDS = {
    "reconnaissance": "probing",
    "enumeration": "probing",
    "injection": "injection patterns",
    "path_traversal": "path traversal patterns",
    "access_control": "access-control probes",
    "credential_attack": "credential attempts",
    "ssrf": "SSRF patterns",
    "exploitation": "exploitation patterns",
}


def suspicious_reasons(profile: ClientProfile) -> tuple[PriorityReason, ...]:
    """Reasons in a fixed order, leaving out any that do not apply to this client.

    Flagged requests, which apply to every client in the queue, then distinct rule
    matches, a probe followed by an attack pattern, detections across sessions, then
    the per-category reasons profiling wrote.
    """
    context = [
        reason
        for reason in (_distinct(profile), _sequence(profile), _recurrence(profile))
        if reason is not None
    ]
    return (_support(profile), *context, *profile.reasons)


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count:,} {word if count == 1 else plural or word + 's'}"


def _support(profile: ClientProfile) -> PriorityReason:
    flagged, requests = profile.hostile_requests, profile.requests
    severity = Severity(profile.severity).name.lower()
    return PriorityReason(
        f"{flagged:,} of {requests:,} requests flagged ({flagged / requests:.0%}); "
        f"strongest severity {severity}.",
        tuple(dict.fromkeys(ref for reason in profile.reasons for ref in reason.evidence))[
            :SAMPLE_SIZE
        ],
        kind="support",
        why=_support_why(profile),
        summary=f"{flagged:,} of {requests:,} requests flagged; strongest {severity}",
    )


def _support_why(profile: ClientProfile) -> str:
    """What the count and share mean for this client, and when one rule explains them all.

    Most means half or more of the client's requests; a small part means under a
    tenth. A category is named when it holds at least half of the flagged requests.
    """
    flagged = profile.hostile_requests
    if flagged == 1:
        return "A single flagged request: inspect it before relying on it."
    whole = [rule for rule, count in profile.hostile_rules.items() if count == flagged]
    if whole:
        name = profile.hostile_rule_names.get(whole[0], whole[0])
        return (
            f"Every flagged request matches one rule ({name}), so check that rule's "
            "matches before relying on the count."
        )
    counts = profile.category_counts
    top = max(counts, key=lambda category: (counts[category], category)) if counts else None
    if top is not None and counts[top] * 2 >= flagged:
        subject = f"Flagged requests, mostly {KINDS.get(top, top.replace('_', ' '))},"
    else:
        subject = "Flagged requests of several kinds"
    share = flagged / profile.requests
    if share >= 0.5:
        return (
            f"{subject} make up most of this client's recorded activity "
            "rather than a few isolated requests."
        )
    if share >= 0.1:
        return f"{subject} are a substantial part of this client's recorded activity."
    return (
        f"{subject} are a small part of this client's recorded activity; the rest was not flagged."
    )


def _distinct(profile: ClientProfile) -> PriorityReason | None:
    pairs = profile.distinct_rule_pairs
    if not pairs:
        return None
    return PriorityReason(
        f"{_plural(pairs, 'rule')} matched on {_plural(pairs, 'request')}.",
        tuple(example.evidence for example in profile.distinct_examples),
        kind="distinct_rules",
        why=(
            "Distinct rule matches provide support beyond repetition of one rule."
            if pairs > 1
            else "One rule matched here. Its rating describes the rule, not this request, "
            "so inspect the request before relying on it."
        ),
        summary=_plural(pairs, "distinct rule match", "distinct rule matches"),
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


def _seconds(first: str, last: str) -> float:
    return (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds()


def _span(seconds: float) -> str:
    """Whole units, rounded down: minutes under an hour, hours under two days, else days."""
    if seconds < 60:
        return "less than a minute"
    if seconds < 3600:
        return _plural(int(seconds // 60), "minute")
    if seconds < 48 * 3600:
        return _plural(int(seconds // 3600), "hour")
    return _plural(int(seconds // 86400), "day")


def _recurrence(profile: ClientProfile) -> PriorityReason | None:
    """Detections in two or more sessions; under an hour apart they may be one burst."""
    hostile, sessions = profile.hostile_sessions, profile.sessions
    if hostile < 2 or profile.first_hostile is None or profile.last_hostile is None:
        return None
    seconds = _seconds(profile.first_hostile, profile.last_hostile)
    return PriorityReason(
        f"Hostile detections occurred in {hostile:,} of {sessions:,} sessions. "
        f"The first and last matching requests were {_span(seconds)} apart.",
        tuple(example.evidence for example in profile.recurrence_examples),
        kind="recurrence",
        why=(
            "The sessions are close together, so they may be one burst split by a session boundary."
            if seconds < 3600
            else "Review the matching requests across these sessions to see whether "
            "their behaviour is related."
        ),
        summary=f"Detections in {hostile:,} of {sessions:,} sessions",
        examples=profile.recurrence_examples,
    )
