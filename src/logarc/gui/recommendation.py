"""The details a queue shows for one recommendation, as HTML for a text browser.

One block per reason: what was observed, why it deserves attention, and example
requests the reader can click to open in reconstruction. Everything taken from a
log is escaped. A reference whose source cannot be read stays visible with the
reason, and nothing is substituted for it.

Anchors are `reason:<n>`, which opens a reason's evidence, `example:<n>:<m>`,
which opens one example request, and `expand:<n>:<m>`, which asks for that
example's full request path. `details:<n>` toggles one finding and `context:0`
toggles measurements and coverage; `parse_anchor` reads them back.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from typing import TYPE_CHECKING

from logarc.style import plural
from logarc.triage.profile import FEATURES, HIGH_CONFIDENCE

if TYPE_CHECKING:
    from collections.abc import Mapping

    from PyQt6.QtCore import QUrl

    from logarc.core.evidence import EvidenceRef
    from logarc.triage.profile import PriorityReason, RankedClient, RequestExample

TITLES = {
    "exploit_evidence": "Exploit evidence",
    "support": "Flagged requests",
    "distinct_rules": "Distinct rule matches",
    "sequence": "Probe, then an attack pattern",
    "recurrence": "Recurrence across sessions",
}

#: What a block's count rests on, where the observation alone would not say.
NOTES = {
    "distinct_rules": f"Counted: bundled rules rated at confidence {HIGH_CONFIDENCE} or above. "
    "The rating describes the rule, not the request.",
}


@dataclass(frozen=True)
class SourceStatus:
    """What reading a referenced line found, when it was not simply the line."""

    note: str
    can_open: bool
    """False when the line could not be read at all; True when it was read from a
    source that has changed since ingest, which still opens, with its warning."""


def summary_for(row: RankedClient) -> str:
    """The compact observation the queue's table shows for a row."""
    if not row.reasons:
        return "No hostile detection"
    first = row.reasons[0]
    return first.summary or first.text


def render_recommendation(
    row: RankedClient,
    status: Mapping[EvidenceRef, SourceStatus] | None = None,
    *,
    path_chars: int | None = None,
    expanded: frozenset[tuple[int, int]] = frozenset(),
    opened: frozenset[int] = frozenset(),
    show_context: bool = False,
) -> str:
    """The details area for `row`.

    `status` marks references that did not read cleanly. `path_chars` is how much of
    a request path fits the space given to it, measured by the caller; a longer path
    is cut there with a link to show it whole, unless its (reason, example) is in
    `expanded`. Findings start with a compact observation; `opened` selects
    those whose explanations and examples are shown. Measurements and coverage
    appear only when `show_context` is requested.
    """
    status = status or {}
    profile = row.profile
    parts = [
        f"<p><b>{escape(profile.client_ip)}</b><br>"
        f"{plural(profile.requests, 'request')} · "
        f"{plural(profile.hostile_requests, 'flagged request')}</p>"
    ]
    if status:
        unavailable = sum(not state.can_open for state in status.values())
        warnings = len(status) - unavailable
        notes = []
        if unavailable:
            notes.append(f"{plural(unavailable, 'sample source line')} unavailable")
        if warnings:
            notes.append(f"{plural(warnings, 'sample source line')} with warnings")
        parts.append(
            "<p><b>Source warning:</b> " + "; ".join(notes) + ". Open a finding for details.</p>"
        )
    for number, reason in enumerate(row.reasons):
        parts.append(_block(number, reason, status, path_chars, expanded, number in opened))
    mark = "\u25bc" if show_context else "\u25b6"
    parts.append(f'<p><b><a href="context:0">{mark} More context</a></b></p>')
    if not show_context:
        return "".join(parts)
    responses = ", ".join(f"{code}: {count}" for code, count in profile.statuses.items())
    lines = [
        f"Responses: {responses or 'not recorded'}. "
        "A 200 response alone does not establish that an attack succeeded.",
        "Examples and source lines are samples, not the complete supporting set.",
        "",
        "Recorded measurements:",
        *(f"{FEATURES[name]}: {value:,.3g}" for name, value in profile.features.items()),
        "",
        "Field coverage:",
        *(
            f"{name}: {count:,}/{profile.requests:,} requests"
            for name, count in profile.coverage.items()
        ),
    ]
    parts.append("<p>" + "<br>".join(escape(line) for line in lines) + "</p>")
    return "".join(parts)


def _block(
    number: int,
    reason: PriorityReason,
    status: Mapping[EvidenceRef, SourceStatus],
    path_chars: int | None,
    expanded: frozenset[tuple[int, int]],
    opened: bool,
) -> str:
    title = TITLES.get(reason.kind, FEATURES.get(reason.metric, "Activity indicator"))
    mark = "\u25bc" if opened else "\u25b6"
    lines = [f'<b><a href="details:{number}">{mark} {number + 1}. {escape(title)}</a></b>']
    if not opened:
        lines.append(escape(reason.summary or reason.text))
        return "<p>" + "<br>".join(lines) + "</p>"
    observed = f'<a href="reason:{number}">{escape(reason.text)}</a>'
    lines.append(f"Observed: {observed}" if title else observed)
    if reason.why:
        lines.append(f"Why: {escape(reason.why)}")
    if reason.kind in NOTES:
        lines.append(f"<small>{escape(NOTES[reason.kind])}</small>")
    if reason.examples:
        lines.append(f"Examples: {len(reason.examples)} shown")
        lines.extend(
            _example(
                number,
                index,
                item,
                status.get(item.evidence),
                None if (number, index) in expanded else path_chars,
            )
            for index, item in enumerate(reason.examples)
        )
    elif reason.evidence:
        lines.append(
            "Sample source lines: " + ", ".join(_ref(ref, status) for ref in reason.evidence)
        )
    return "<p>" + "<br>".join(lines) + "</p>"


def _when(timestamp: str) -> str:
    """A recorded time in UTC, the way reconstruction shows it, date included."""
    try:
        moment = datetime.fromisoformat(timestamp)
    except ValueError:
        return timestamp
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _example(
    number: int,
    index: int,
    item: RequestExample,
    state: SourceStatus | None,
    path_chars: int | None,
) -> str:
    target = (item.path or "") + (f"?{item.query}" if item.query else "")
    cut = path_chars is not None and len(target) > path_chars
    if cut and path_chars is not None:
        target = target[: max(path_chars - 1, 1)] + "\u2026"
    request = " ".join(part for part in (item.method, target) if part)
    label = escape(request + (f" ({item.note})" if item.note else ""))
    reference = escape(str(item.evidence))
    more = f' <a href="expand:{number}:{index}">Show full request</a>' if cut else ""
    when = escape(_when(item.timestamp))
    if state is not None and not state.can_open:
        return (
            f"{label}{more}<br>{when}<br>"
            f"<small>{reference}. Cannot open: {escape(state.note)}</small>"
        )
    warning = f". Warning: {escape(state.note)}" if state is not None else ""
    return (
        f'<a href="example:{number}:{index}">{label}</a>{more}<br>{when}<br>'
        f"<small>{reference}{warning}</small>"
    )


def _ref(ref: EvidenceRef, status: Mapping[EvidenceRef, SourceStatus]) -> str:
    state = status.get(ref)
    if state is None:
        return escape(str(ref))
    word = "warning" if state.can_open else "cannot open"
    return escape(f"{ref} ({word}: {state.note})")


def parse_anchor(url: QUrl) -> tuple[str, int, int] | None:
    """Read only the evidence, example, disclosure and context anchors written here."""
    scheme, path = url.scheme(), url.path()
    parts = path.split(":")
    if scheme in ("reason", "details") and len(parts) == 1 and parts[0].isdigit():
        return (scheme, int(parts[0]), -1)
    if scheme == "context" and path == "0":
        return ("context", 0, -1)
    if scheme in ("example", "expand") and len(parts) == 2 and all(p.isdigit() for p in parts):
        return (scheme, int(parts[0]), int(parts[1]))
    return None
