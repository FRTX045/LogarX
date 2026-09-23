"""The details a queue shows for one recommendation, as HTML for a text browser.

One block per reason: what was observed, why it deserves attention, and example
requests the reader can click to open in reconstruction. Everything taken from a
log is escaped. A reference whose source cannot be read stays visible with the
reason, and nothing is substituted for it.

Anchors are `reason:<n>`, which opens a reason's evidence, and
`example:<n>:<m>`, which opens one example request; `parse_anchor` reads them back.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import TYPE_CHECKING

from logarc.triage.profile import FEATURES

if TYPE_CHECKING:
    from collections.abc import Mapping

    from PyQt6.QtCore import QUrl

    from logarc.core.evidence import EvidenceRef
    from logarc.triage.profile import PriorityReason, RankedClient, RequestExample

TITLES = {
    "distinct_rules": "High-confidence rule matches",
    "sequence": "Probe, then an attack pattern",
    "recurrence": "Recurrence across sessions",
    "support": "Support, share and severity",
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
    row: RankedClient, status: Mapping[EvidenceRef, SourceStatus] | None = None
) -> str:
    """The details area for `row`; `status` marks references that did not read cleanly."""
    status = status or {}
    parts = [f"<p><b>{escape(row.profile.client_ip)}</b></p>"]
    for number, reason in enumerate(row.reasons):
        parts.append(_block(number, reason, status))
    profile = row.profile
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


def _block(number: int, reason: PriorityReason, status: Mapping[EvidenceRef, SourceStatus]) -> str:
    title = TITLES.get(reason.kind)
    lines = [f"<b>{number + 1}. {escape(title)}</b>"] if title else []
    observed = f'<a href="reason:{number}">{escape(reason.text)}</a>'
    lines.append(f"Observed: {observed}" if title else observed)
    if reason.why:
        lines.append(f"Why: {escape(reason.why)}")
    if reason.examples:
        lines.append(f"Examples: {len(reason.examples)} shown")
        lines.extend(
            _example(number, index, item, status.get(item.evidence))
            for index, item in enumerate(reason.examples)
        )
    elif reason.evidence:
        lines.append(
            "Sample source lines: " + ", ".join(_ref(ref, status) for ref in reason.evidence)
        )
    return "<p>" + "<br>".join(lines) + "</p>"


def _example(number: int, index: int, item: RequestExample, state: SourceStatus | None) -> str:
    label = escape(
        " ".join(part for part in (item.method, item.path, item.timestamp) if part)
        + (f" ({item.note})" if item.note else "")
    )
    reference = escape(str(item.evidence))
    if state is not None and not state.can_open:
        return f"{label}<br><small>{reference}. Cannot open: {escape(state.note)}</small>"
    warning = f". Warning: {escape(state.note)}" if state is not None else ""
    return f'<a href="example:{number}:{index}">{label}</a><br><small>{reference}{warning}</small>'


def _ref(ref: EvidenceRef, status: Mapping[EvidenceRef, SourceStatus]) -> str:
    state = status.get(ref)
    if state is None:
        return escape(str(ref))
    word = "warning" if state.can_open else "cannot open"
    return escape(f"{ref} ({word}: {state.note})")


def parse_anchor(url: QUrl) -> tuple[str, int, int] | None:
    """`("reason", n, -1)` or `("example", n, m)` for an anchor this module wrote, else None."""
    scheme, path = url.scheme(), url.path()
    parts = path.split(":")
    if scheme == "reason" and len(parts) == 1 and parts[0].isdigit():
        return ("reason", int(parts[0]), -1)
    if scheme == "example" and len(parts) == 2 and all(part.isdigit() for part in parts):
        return ("example", int(parts[0]), int(parts[1]))
    return None
