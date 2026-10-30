"""Property-based tests for the LogFormat compiler.

The example-based tests cover the formats we thought of. These cover the ones we
did not: any ordering of any supported directives, carrying values containing
quotes, backslashes and control bytes, must survive a render/parse round trip.

That round trip is the whole generality claim — if it holds, a site running a
custom `LogFormat` is supported without new code.
"""

from __future__ import annotations

import string
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from zodiarc.core.evidence import EvidenceRef
from zodiarc.parsers.logformat import LogFormatParser

REF = EvidenceRef(source_file_id="prop", line_no=1)

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def apache_escape(value: str) -> str:
    """Render a value the way Apache writes it inside a quoted field."""
    out = []
    for char in value:
        if char in ('"', "\\"):
            out.append("\\" + char)
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(f"\\x{ord(char):02x}")
        else:
            out.append(char)
    return "".join(out)


def render_clf_time(moment: datetime) -> str:
    offset = moment.utcoffset() or timedelta(0)
    total = int(offset.total_seconds()) // 60
    sign = "+" if total >= 0 else "-"
    hours, minutes = divmod(abs(total), 60)
    return (
        f"[{moment.day:02d}/{MONTHS[moment.month - 1]}/{moment.year:04d}:"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} "
        f"{sign}{hours:02d}{minutes:02d}]"
    )


@dataclass(frozen=True)
class Slot:
    """One optional directive, plus how to render a value for it."""

    spec: str
    render: Callable[[str], str]


# Values for bare fields: non-empty and free of whitespace, as Apache guarantees.
bare_text = st.text(alphabet=string.ascii_letters + string.digits + "._-/", min_size=1, max_size=20)

# Values for quoted fields: deliberately nasty, since these carry attack payloads.
#
# A lone "-" is excluded because it is genuinely ambiguous in the format rather
# than a defect in the parser: Apache writes "-" for an absent header, so a
# client sending a header of exactly "-" is indistinguishable from one sending
# none. See `_clean` in logformat.py.
quoted_text = st.text(
    alphabet=st.sampled_from([*string.printable[:94], '"', "\\", "\x00", "\x1b", "\n", "\t"]),
    min_size=1,
    max_size=40,
).filter(lambda value: value != "-")

timestamps = st.datetimes(
    min_value=datetime(1990, 1, 1),
    max_value=datetime(2035, 12, 31),
).map(lambda d: d.replace(microsecond=0, tzinfo=UTC))

offsets = st.integers(min_value=-12 * 60, max_value=14 * 60).map(
    lambda m: timezone(timedelta(minutes=m))
)

ip_addresses = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    *[st.integers(min_value=0, max_value=255)] * 4,
)

status_codes = st.integers(min_value=100, max_value=599)

#: Optional directives that may appear, in any order, after the required ones.
OPTIONAL_SLOTS = [
    Slot('"%{Referer}i"', lambda v: f'"{apache_escape(v)}"'),
    Slot('"%{User-Agent}i"', lambda v: f'"{apache_escape(v)}"'),
    Slot("%l", lambda v: v),
    Slot("%u", lambda v: v),
    Slot("%D", lambda v: v),
    Slot("%v", lambda v: v),
]


@settings(max_examples=200, deadline=None)
@given(
    ip=ip_addresses,
    moment=timestamps,
    tz=offsets,
    status=status_codes,
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
    path=bare_text.map(lambda t: "/" + t),
    chosen=st.lists(st.sampled_from(range(len(OPTIONAL_SLOTS))), unique=True, max_size=6),
    filler=bare_text,
)
def test_any_arrangement_of_directives_round_trips(
    ip: str,
    moment: datetime,
    tz: timezone,
    status: int,
    method: str,
    path: str,
    chosen: list[int],
    filler: str,
) -> None:
    localised = moment.astimezone(tz)

    specs = ["%h", "%t", '"%r"', "%>s"]
    values = [ip, render_clf_time(localised), f'"{method} {path} HTTP/1.1"', str(status)]
    for index in chosen:
        slot = OPTIONAL_SLOTS[index]
        specs.append(slot.spec)
        values.append(slot.render(filler))

    parser = LogFormatParser(" ".join(specs))
    event = parser.parse_line(" ".join(values), REF)

    assert event is not None
    assert event.client_ip == ip
    assert event.timestamp == moment
    assert event.status == status
    assert event.method == method
    assert event.path == path


@settings(max_examples=200, deadline=None)
@given(agent=quoted_text)
def test_quoted_field_contents_survive_escaping(agent: str) -> None:
    """Attack payloads live in quoted fields. If escaping does not round trip,
    a rule matches the escaped text rather than what the client actually sent."""
    parser = LogFormatParser('%h %t "%r" %>s "%{User-Agent}i"')
    line = (
        f"1.2.3.4 {render_clf_time(datetime(2020, 1, 1, tzinfo=UTC))} "
        f'"GET / HTTP/1.1" 200 "{apache_escape(agent)}"'
    )

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.user_agent == agent


@settings(max_examples=100, deadline=None)
@given(moment=timestamps, tz=offsets)
def test_timestamps_from_any_timezone_normalise_to_the_same_instant(
    moment: datetime, tz: timezone
) -> None:
    parser = LogFormatParser("%h %t")
    line = f"1.2.3.4 {render_clf_time(moment.astimezone(tz))}"

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.timestamp == moment
    assert event.timestamp.tzinfo == UTC
