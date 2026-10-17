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

from logarc.style import THEME, plural
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

# QTextDocument supports tables and paragraph spacing, but not browser layout
# features such as flexbox or rounded cards. Keep this native rich text and use
# the same surfaces and type colours as the rest of the desktop interface.
_STYLES = f"""<style>
p {{ margin-top: 0; margin-bottom: 10px; }}
a {{ color: {THEME.accent}; }}
.secondary {{ color: {THEME.muted}; }}
.identity {{ color: {THEME.identity}; }}
.timestamp {{ color: {THEME.timestamp}; }}
.caution {{ color: {THEME.warning}; }}
.error {{ color: {THEME.alert}; }}
.section {{ margin-top: 14px; margin-bottom: 6px; }}
.disclosure {{ color: {THEME.ink}; text-decoration: none; }}
.context {{ color: {THEME.muted}; text-decoration: none; }}
</style>"""


def _card(content: str) -> str:
    """A padded finding with a quiet surface and space before the next one."""
    return (
        f'<table width="100%" cellspacing="0" cellpadding="12" '
        f'bgcolor="{THEME.raised}" style="border: 1px solid {THEME.line};">'
        f"<tr><td>{content}</td></tr></table>"
        '<p style="margin-top: 0; margin-bottom: 0; font-size: 8px;">&nbsp;</p>'
    )


def _disclosure(anchor: str, title: str, opened: bool, *, context: bool = False) -> str:
    mark = "\u25be" if opened else "\u25b8"
    role = "context" if context else "disclosure"
    return f'<a class="{role}" href="{anchor}">{mark} {escape(title)}</a>'


def _measurements(items: Mapping[str, str]) -> str:
    """Aligned labels and values; cells can wrap in a narrow panel."""
    return (
        '<table width="100%" cellspacing="0" cellpadding="4">'
        + "".join(
            f'<tr><td class="secondary">{escape(label)}:</td>'
            f'<td align="right">{escape(value)}</td></tr>'
            for label, value in items.items()
        )
        + "</table>"
    )


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
        _STYLES,
        f'<p class="identity" style="margin-bottom: 4px;"><b>{escape(profile.client_ip)}</b></p>'
        '<p class="secondary">'
        f"{plural(profile.requests, 'request')} · "
        f'<span class="{"caution" if profile.hostile_requests else "secondary"}">'
        f"{plural(profile.hostile_requests, 'flagged request')}</span></p>",
        f'<p class="secondary">{plural(len(row.reasons), "finding")} · Open to see evidence.</p>',
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
            '<p class="error"><b>Source warning:</b> '
            + "; ".join(notes)
            + ". Open a finding for details.</p>"
        )
    for number, reason in enumerate(row.reasons):
        parts.append(_block(number, reason, status, path_chars, expanded, number in opened))
    parts.append(
        '<p class="section"><b>'
        + _disclosure("context:0", "More context", show_context, context=True)
        + "</b></p>"
    )
    if not show_context:
        return "".join(parts)
    responses = ", ".join(f"{code}: {count:,}" for code, count in profile.statuses.items())
    parts.extend(
        [
            f"<p>Responses: {escape(responses or 'not recorded')}.</p>",
            '<p class="secondary">A 200 response alone does not establish that an attack '
            "succeeded. Examples and source lines are samples, not the complete supporting set.</p>",
            '<p class="section"><b>Recorded measurements:</b></p>',
            _measurements(
                {
                    FEATURES[name]: f"{value:,.0f}" if value % 1 == 0 else f"{value:,.3g}"
                    for name, value in profile.features.items()
                }
            ),
            '<p class="section"><b>Field coverage:</b></p>',
            _measurements(
                {
                    name: f"{count:,}/{profile.requests:,} requests"
                    for name, count in profile.coverage.items()
                }
            ),
        ]
    )
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
    lines = [
        "<p><b>" + _disclosure(f"details:{number}", f"{number + 1}. {title}", opened) + "</b></p>"
    ]
    if not opened:
        lines.append(f'<p class="secondary">{escape(reason.summary or reason.text)}</p>')
        return _card("".join(lines))
    lines.append(f"<p><b>Observed:</b><br>{escape(reason.text)}</p>")
    if reason.why:
        lines.append(f"<p><b>Why:</b><br>{escape(reason.why)}</p>")
    if reason.kind in NOTES:
        lines.append(f'<p class="secondary">{escape(NOTES[reason.kind])}</p>')
    lines.append(f'<p><a href="reason:{number}">Inspect supporting requests</a></p>')
    if reason.examples:
        lines.append(f'<p class="section"><b>Examples: {len(reason.examples)} shown</b></p>')
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
            '<p class="section"><b>Sample source lines:</b></p>'
            '<p class="secondary">'
            + "<br>".join(_ref(ref, status) for ref in reason.evidence)
            + "</p>"
        )
    return _card("".join(lines))


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
    label = escape(request)
    note = f'<br><span class="secondary">{escape(item.note)}</span>' if item.note else ""
    reference = escape(str(item.evidence))
    more = f'<br><a href="expand:{number}:{index}">Show full request</a>' if cut else ""
    when = escape(_when(item.timestamp))
    if state is not None and not state.can_open:
        return (
            f"<p>{label}{more}{note}<br>"
            f'<span class="timestamp">{when}</span> · '
            f'<span class="secondary">{reference}</span><br>'
            f'<span class="error">Cannot open: {escape(state.note)}</span></p>'
        )
    warning = (
        f'<br><span class="error">Warning: {escape(state.note)}</span>' if state is not None else ""
    )
    return (
        f'<p><a href="example:{number}:{index}">{label}</a>{more}{note}<br>'
        f'<span class="timestamp">{when}</span> · '
        f'<span class="secondary">{reference}</span>{warning}</p>'
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
