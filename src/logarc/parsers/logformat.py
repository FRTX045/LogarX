"""Compiles Apache `LogFormat` directives into line parsers.

Rather than hardcoding "combined" and "common", this compiles the actual
directive string an administrator wrote in their Apache config. That covers the
standard formats and any custom Apache one.

**Apache directives only.** An nginx `log_format` definition is written in
`$variable` syntax and is rejected outright — `LogFormatError: no directives
found`. What is true of nginx is a different statement: its default `combined`
*output* is byte-identical to Apache's, so an nginx access log is read by
`apache-combined` (measured: detected at confidence 1.0). Reading an nginx log
works; pasting an nginx format definition does not. The docstring used to claim
the second, which sent anyone with a custom nginx format to a dead end.

Supported directive syntax::

    %h  %{User-Agent}i  %>s  %400,501{Referer}i  %%
    %{%Y-%m-%dT%H:%M:%S%z}t          # a time format of the site's own

A `%{...}t` is read as a strftime pattern, turned into a regex from it, and
parsed back with the same pattern — so the shape the field is matched against
and the shape it is read with cannot disagree. Apache's own named time tokens
(`%{sec}t`, `%{begin:...}t`) are refused by name rather than misread as
strftime. The plain `%t` keeps its hand-sliced CLF fast path, which runs on
every ordinary line and is about ten times quicker than `strptime`.

Conditional prefixes (``%400,501...``) are parsed and ignored: they control
whether Apache *writes* the field, which we cannot recover after the fact, and
the field is already optional on our side.

How far a field reaches is read from what surrounds it in the format. Quotes
delimit one, spaces and all; so do literal brackets, and a field in brackets
may be empty (`[%{upstream}e]` reads `[]`). An unquoted header or variable
followed by a space may be a list, `a, b` or `a : b`, the way Apache and nginx
write repeated headers and retried upstreams; one that ends the line reads to
the end of it. Anything else is one run of non-blank characters. None of this
narrows a field: a line the plain reading accepts is read exactly as before.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from logarc.core.event import NormalizedEvent
from logarc.parsers.base import split_request_line
from logarc.parsers.times import TimeFormatError, check_time_format

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.evidence import EvidenceRef

__all__ = ["LogFormatError", "LogFormatParser"]


class LogFormatError(ValueError):
    """Raised when a LogFormat directive string cannot be compiled."""


# --------------------------------------------------------------------------
# Directive tables
# --------------------------------------------------------------------------

#: Directives taking no argument, mapped to the field name they produce.
_SIMPLE_DIRECTIVES: Final[dict[str, str]] = {
    "h": "remote_host",
    "a": "client_ip",
    "A": "local_ip",
    "l": "remote_logname",
    "u": "remote_user",
    "t": "time",
    "r": "request_line",
    "m": "method",
    "U": "url_path",
    "q": "query_string",
    "H": "protocol",
    "s": "status",
    "b": "bytes_clf",
    "B": "bytes_sent",
    "v": "server_name",
    "V": "server_name",
    "p": "port",
    "D": "duration_us",
    "T": "duration_s",
    "O": "bytes_out",
    "I": "bytes_in",
    "f": "filename",
    "P": "process_id",
    "k": "keepalive_requests",
    "X": "connection_status",
}

#: Directives taking a ``{...}`` argument, mapped to their field-name prefix.
_ARG_DIRECTIVES: Final[dict[str, str]] = {
    "i": "req_header",
    "o": "resp_header",
    "C": "cookie",
    "e": "env",
    "n": "note",
    "p": "port",
    "P": "process",
    "t": "time",
}

#: What each strftime directive writes, as a regex. A `%{...}t` format is
#: turned into a pattern from this and parsed back with `strptime`, so the two
#: cannot disagree about what the field looks like.
#:
#: Deriving it rather than matching the field as one non-blank run is not a
#: refinement: `%d/%b/%Y %H:%M:%S` writes a space, and `\S+` would stop at it
#: and hand the rest of the line to the next field.
_STRFTIME_BODIES: Final[dict[str, str]] = {
    "Y": r"\d{4}",
    "y": r"\d{2}",
    "m": r"\d{2}",
    "d": r"\d{2}",
    "H": r"\d{2}",
    "I": r"\d{2}",
    "M": r"\d{2}",
    "S": r"\d{2}",
    "j": r"\d{3}",
    "f": r"\d{1,6}",
    "b": r"[A-Za-z]{3}",
    "B": r"[A-Za-z]+",
    "a": r"[A-Za-z]{3}",
    "A": r"[A-Za-z]+",
    "p": r"[APap][Mm]",
    "z": r"[+-]\d{2}:?\d{2}",
    "Z": r"[A-Za-z][A-Za-z/_+-]*",
    "%": "%",
}

_DIRECTIVE_RE: Final = re.compile(
    r"""
    %
    (?P<condition>[!0-9,]*)              # conditional status list, e.g. 400,501 or !200
    (?P<modifier>[<>]?)                  # original (<) or final (>) request
    (?:
        \{(?P<arg>[^}]*)\}(?P<argfmt>[a-zA-Z])
      | (?P<fmt>[a-zA-Z%])
    )
    """,
    re.VERBOSE,
)

#: Matches the contents of a double-quoted field, honouring Apache's backslash
#: escaping. Apache escapes `"` and `\`, and renders control bytes as `\xHH`.
_QUOTED_BODY: Final = r'(?:[^"\\]|\\.)*'
_BRACKETED_BODY: Final = r"\[[^\]]*\]"

#: A field the format wraps in literal brackets, other than the time: read up
#: to the closing bracket, as a quoted field is read up to its quote. It may be
#: empty — ingress-nginx writes `[$proxy_alternative_upstream_name]` as `[]` on
#: nearly every line, and a bare body would refuse all of them.
_IN_BRACKETS_BODY: Final = r"[^\]]*"

#: A bare field must consume at least one character. If it could match nothing,
#: a line with a field omitted would still satisfy the pattern and auto-detection
#: would happily pick the wrong format.
_BARE_BODY: Final = r"\S+"

#: `%q` is the exception: it is genuinely empty when a request has no query
#: string, and Apache writes no placeholder for it.
_OPTIONAL_BARE_BODY: Final = r"\S*"

#: A header or a server variable, unquoted, may be a list: Apache and nginx
#: join a repeated header with `, `, and nginx joins the upstreams it tried the
#: same way, and the groups of an internal redirect with ` : `. So the field
#: runs on past a space while its last item ends in a comma, or across a ` : `.
#:
#: Atomic, and that is not a detail. A list that could give items back would
#: let two neighbouring list fields share theirs every possible way before a
#: line was refused, and a forwarded-for header is the client's to write: one
#: crafted request could stall an ingest. This takes what it can and keeps it.
_LIST_BODY: Final = r"(?>\S+(?:(?<=,) \S+| : \S+)*)"

#: The same directives when nothing follows them: nothing says where they
#: stop, so they run to the end of the line, spaces included. ingress-nginx
#: ends its line on `$req_id`, which is the client's own `X-Request-ID` when it
#: sends one, and nginx does not escape a space — read as one token, a request
#: sent with `X-Request-ID: a b` could not be read at all. Atomic for the same
#: reason the list is, though here it only ever trims trailing blanks.
_TO_THE_END_BODY: Final = r"(?>\S(?:.*\S)?)"

#: The directives whose value can be a list: request and response headers,
#: environment variables and notes. A status, a byte count or an address
#: cannot be.
_LIST_DIRECTIVES: Final[frozenset[str]] = frozenset({"i", "o", "e", "n"})

#: UTC offsets already worked out, keyed on the five characters that spell one
#: (`+0000`, `-0330`). Unbounded by type and bounded in fact: there are fewer
#: than forty in use worldwide, and a single log almost always has one.
_OFFSETS: dict[str, timedelta] = {}

_MONTHS: Final[dict[str, int]] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip

#: Fields promoted onto `NormalizedEvent`; everything else lands in `extra`.
_PROMOTED: Final[frozenset[str]] = frozenset(
    {
        "time",
        "remote_host",
        "client_ip",
        "request_line",
        "method",
        "url_path",
        "query_string",
        "protocol",
        "status",
        "bytes_clf",
        "bytes_sent",
        "server_name",
        "req_header_referer",
        "req_header_user_agent",
    }
)


@dataclass(frozen=True, slots=True)
class _Literal:
    text: str


@dataclass(frozen=True, slots=True)
class _Field:
    name: str
    directive: str

    arg: str = ""
    """The `{...}` part, for the directives that take one. Only `%{...}t` reads
    it here: the others need it for the field's name and nothing more."""


def _field_name(match: re.Match[str]) -> str:
    """Derive a stable field name from one directive match."""
    arg, argfmt, fmt = match.group("arg"), match.group("argfmt"), match.group("fmt")

    if fmt is not None:
        name = _SIMPLE_DIRECTIVES.get(fmt)
        if name is None:
            raise LogFormatError(f"unsupported directive %{fmt}")
        return name

    prefix = _ARG_DIRECTIVES.get(argfmt or "")
    if prefix is None:
        raise LogFormatError(f"unsupported directive %{{{arg}}}{argfmt}")
    if argfmt == "t":  # a custom time format, e.g. %{%Y-%m-%d}t
        return "time"
    slug = re.sub(r"[^a-z0-9]+", "_", (arg or "").lower()).strip("_")
    return f"{prefix}_{slug}" if slug else prefix


def _time_pattern(time_format: str) -> str:
    """A regex matching what `strftime(time_format)` would write.

    Refuses anything it cannot account for rather than guessing. A directive
    silently rendered as a literal would compile to a pattern that never
    matches, and the reader would be told their field order was wrong.
    """
    if "%" not in time_format:
        # Apache's own vocabulary — `%{sec}t`, `%{msec}t`, `%{begin:...}t` —
        # rather than strftime. Read as a strftime pattern it would compile to
        # a regex matching the literal text `sec`, which matches nothing and
        # explains nothing.
        raise LogFormatError(
            f"time format {time_format!r} is not a strftime pattern; "
            "logarc reads %{...}t written with strftime directives such as %Y-%m-%d"
        )

    try:
        check_time_format(time_format)
    except TimeFormatError as exc:
        raise LogFormatError(str(exc)) from exc

    parts: list[str] = []
    index = 0
    while index < len(time_format):
        char = time_format[index]
        if char != "%":
            parts.append(re.escape(char))
            index += 1
            continue
        if index + 1 >= len(time_format):
            raise LogFormatError(f"time format {time_format!r} ends in a bare %")
        letter = time_format[index + 1]
        body = _STRFTIME_BODIES.get(letter)
        if body is None:
            raise LogFormatError(f"unsupported time directive %{letter} in {time_format!r}")
        parts.append(body)
        index += 2
    return "".join(parts)


def _tokenize(log_format: str) -> list[_Literal | _Field]:
    tokens: list[_Literal | _Field] = []
    pos = 0
    for match in _DIRECTIVE_RE.finditer(log_format):
        if match.start() > pos:
            tokens.append(_Literal(log_format[pos : match.start()]))
        if match.group("fmt") == "%":
            tokens.append(_Literal("%"))
        else:
            directive = match.group("fmt") or match.group("argfmt") or ""
            tokens.append(_Field(_field_name(match), directive, match.group("arg") or ""))
        pos = match.end()
    if pos < len(log_format):
        tokens.append(_Literal(log_format[pos:]))
    return tokens


def _body_pattern(token: _Field, prev: str, nxt: str, *, last: bool, widened: bool) -> str:
    """Choose the regex body for a field from how it is delimited in the format.

    A field wrapped in literal quotes may contain spaces; a bare one may not.
    Getting this from the format string rather than from a hardcoded list is
    what lets custom formats work without special cases.

    `widened` adds what brackets, lists and the end of the line allow. Without
    it this is the plain reading, which a format falls back to: see
    `_CompiledFormat.fallback`.
    """
    if prev.endswith('"') and nxt.startswith('"'):
        return _QUOTED_BODY
    if token.directive == "t" and token.arg:
        return _time_pattern(token.arg)
    if widened and token.directive != "t" and prev.endswith("[") and nxt.startswith("]"):
        return _IN_BRACKETS_BODY
    if token.directive == "t" and not (prev.endswith("[") or nxt.startswith("]")):
        return _BRACKETED_BODY
    if token.directive == "q":
        return _OPTIONAL_BARE_BODY
    if widened and token.directive in _LIST_DIRECTIVES:
        # Only where a space or the end of the line follows. A format that
        # writes its own `, ` after the field, or a unit such as Traefik's
        # `4ms`, or another field straight after it, means the field ends
        # there, and an atomic list would swallow what came next.
        if last:
            return _TO_THE_END_BODY
        if nxt.startswith(" ") and not nxt.startswith(" : "):
            return _LIST_BODY
    return _BARE_BODY


@dataclass(frozen=True, slots=True)
class _Slots:
    """Where each promoted field sits in a match's tuple of groups.

    A field this format does not write points at `absent` — one past the last
    group, where a `None` sentinel is appended — so every read is an
    unconditional index rather than a dict lookup that might miss.
    """

    absent: int
    time: int
    client_ip: int
    remote_host: int
    request_line: int
    method: int
    url_path: int
    query_string: int
    protocol: int
    status: int
    bytes_clf: int
    bytes_sent: int
    server_name: int
    referer: int
    user_agent: int


@dataclass(frozen=True, slots=True)
class _CompiledFormat:
    pattern: re.Pattern[str]
    slots: _Slots

    quoted_slots: tuple[int, ...]
    """Groups the format wrapped in quotes, as indices into a match's groups.
    Those carry Apache's backslash escaping and are the only ones unescaped."""

    extra_slots: tuple[tuple[str, int], ...]
    """Groups with no place in the canonical schema, as (field name, index)."""

    fallback: re.Pattern[str] | None = None
    """The plain reading, tried when `pattern` refuses a line; `None` when the
    two are the same.

    Brackets, lists and the end of the line let a field hold more, and that
    must never cost a line the plain reading accepted. It could: a
    forwarded-for the client ended with a comma would run on into the next
    field, and `[a]b]` stops at the first bracket. Both are the client's to
    write, so either would let a request keep itself out of a case. Wherever
    both readings accept a line they read it the same way — the plain one
    takes one token per field, and a widened field that took more would leave
    a later one with none — so trying the widened one first changes nothing
    the plain one already read. The groups are the same in both, so `slots`
    serves either."""

    time_format: str | None = None
    """The strftime pattern from a `%{...}t`, when the format used one.

    `None` for the ordinary `%t`, which takes the CLF fast path — hand-sliced
    because it runs once per line and `strptime` is roughly an order of
    magnitude slower. A site with its own time format pays that cost; every
    other log does not."""


def _slots_for(pattern: re.Pattern[str]) -> _Slots:
    """Resolve the promoted field names to group indices, once per format."""
    index_of = {name: number - 1 for name, number in pattern.groupindex.items()}
    absent = pattern.groups
    return _Slots(
        absent=absent,
        time=index_of.get("time", absent),
        client_ip=index_of.get("client_ip", absent),
        remote_host=index_of.get("remote_host", absent),
        request_line=index_of.get("request_line", absent),
        method=index_of.get("method", absent),
        url_path=index_of.get("url_path", absent),
        query_string=index_of.get("query_string", absent),
        protocol=index_of.get("protocol", absent),
        status=index_of.get("status", absent),
        bytes_clf=index_of.get("bytes_clf", absent),
        bytes_sent=index_of.get("bytes_sent", absent),
        server_name=index_of.get("server_name", absent),
        referer=index_of.get("req_header_referer", absent),
        user_agent=index_of.get("req_header_user_agent", absent),
    )


def _compile(log_format: str) -> _CompiledFormat:
    tokens = _tokenize(log_format)
    if not any(isinstance(t, _Field) for t in tokens):
        raise LogFormatError(f"no directives found in log format: {log_format!r}")

    parts: list[str] = []
    plain: list[str] = []
    quoted: set[str] = set()
    seen: dict[str, int] = {}
    for index, token in enumerate(tokens):
        if isinstance(token, _Literal):
            parts.append(re.escape(token.text))
            plain.append(re.escape(token.text))
            continue

        preceding = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        prev = preceding.text if isinstance(preceding, _Literal) else ""
        nxt = following.text if isinstance(following, _Literal) else ""
        last = following is None

        # A format may legitimately repeat a directive; group names must stay unique.
        count = seen.get(token.name, 0)
        seen[token.name] = count + 1
        group = token.name if count == 0 else f"{token.name}__{count}"

        body = _body_pattern(token, prev, nxt, last=last, widened=True)
        if body is _QUOTED_BODY:
            quoted.add(group)
        parts.append(f"(?P<{group}>{body})")
        plain.append(f"(?P<{group}>{_body_pattern(token, prev, nxt, last=last, widened=False)})")

    try:
        pattern = re.compile("^" + "".join(parts) + r"\s*$")
        fallback = re.compile("^" + "".join(plain) + r"\s*$")
    except re.error as exc:  # pragma: no cover - defensive; _field_name rejects bad names
        raise LogFormatError(f"could not compile log format {log_format!r}: {exc}") from exc

    index_of = {name: number - 1 for name, number in pattern.groupindex.items()}
    custom_time = next(
        (token.arg for token in tokens if isinstance(token, _Field) and token.directive == "t"),
        "",
    )
    return _CompiledFormat(
        pattern=pattern,
        slots=_slots_for(pattern),
        quoted_slots=tuple(sorted(index_of[name] for name in quoted)),
        extra_slots=tuple(
            (name, index) for name, index in index_of.items() if name not in _PROMOTED
        ),
        fallback=None if fallback.pattern == pattern.pattern else fallback,
        time_format=custom_time or None,
    )


# --------------------------------------------------------------------------
# Field conversion
# --------------------------------------------------------------------------


#: Appended to every match's groups, so a field the format does not write has
#: somewhere to point rather than needing a test of its own.
_NOTHING: Final[tuple[None]] = (None,)

_ESCAPE_RE: Final = re.compile(r'\\(x[0-9a-fA-F]{2}|[nrtvf"\\])')
_SIMPLE_ESCAPES: Final[dict[str, str]] = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "f": "\f",
    '"': '"',
    "\\": "\\",
}


def _expand_escape(match: re.Match[str]) -> str:
    token = match.group(1)
    return chr(int(token[1:], 16)) if token[0] == "x" else _SIMPLE_ESCAPES[token]


def _unescape(text: str) -> str:
    """Reverse Apache's escaping of a quoted field.

    Apache writes `"` as `\\"`, backslash as `\\\\`, and any non-printable byte
    as `\\xHH`. Detection rules must see the bytes the client actually sent, so
    this is undone before matching — a payload hidden behind `\\x` escaping
    would otherwise slip past every signature.

    Only applied to fields the format wrapped in quotes: a bare field may
    contain a literal backslash sequence that was never escaping to begin with.
    """
    return _ESCAPE_RE.sub(_expand_escape, text) if "\\" in text else text


def _parse_timestamp(raw: str | None) -> datetime | None:
    """Parse a CLF timestamp such as ``[10/Oct/2000:13:55:36 -0700]`` into UTC.

    Hand-rolled rather than `strptime` because this runs once per line and
    `strptime` is roughly an order of magnitude slower. The layout is fixed
    width, so slicing is safe; anything that does not fit falls through to the
    slow path.
    """
    if not raw:
        return None
    text = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        # Built in UTC and shifted, rather than built in the log's own zone and
        # converted. `astimezone` is the expensive half of this and it needs a
        # `timezone` object to convert from, which was one more allocation per
        # line; subtracting the offset from a UTC datetime reaches the same
        # instant with neither. A log usually has one offset throughout, so the
        # shift itself is cached on the five characters that spell it.
        offset = _OFFSETS.get(zone := text[21:26])
        if offset is None:
            offset = _OFFSETS[zone] = timedelta(hours=int(zone[1:3]), minutes=int(zone[3:5])) * (
                1 if zone[0] == "+" else -1
            )
        return (
            datetime(
                year=int(text[7:11]),
                month=_MONTHS[text[3:6]],
                day=int(text[0:2]),
                hour=int(text[12:14]),
                minute=int(text[15:17]),
                second=int(text[18:20]),
                tzinfo=UTC,
            )
            - offset
        )
    except (ValueError, KeyError, IndexError):
        return _parse_timestamp_fallback(text)


def _parse_custom_timestamp(raw: str | None, time_format: str) -> datetime | None:
    """Read a timestamp written by the format's own `%{...}t` pattern.

    A stamp with no offset is read as UTC, which is what the fallback below
    already did: guessing the reader's local zone would make one log parse to
    different instants on two machines, and a case may not do that.
    """
    if not raw:
        return None
    try:
        parsed = datetime.strptime(raw, time_format)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)


def _parse_timestamp_fallback(text: str) -> datetime | None:
    """Handle a bracketed ``%t`` whose contents turn out not to be CLF.

    Written for custom ``%{...}t`` formats, which now compile a pattern of
    their own and never reach here. What is left is the server that writes
    ``%t`` — brackets and all, that being how Apache writes it — and puts
    something other than a CLF stamp inside. Worth catching, because the
    alternative is quarantining every line of an otherwise readable log.
    """
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)
    return None


def _as_int(raw: str | None) -> int | None:
    """Convert a numeric log field, treating Apache's ``-`` placeholder as absent."""
    if not raw or raw == "-":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _clean(raw: str | None) -> str | None:
    """Normalise an optional text field, treating ``-`` as absent.

    This is ambiguous and unavoidably so: Apache writes ``"-"`` for a missing
    header, and a client that genuinely sends a header of ``-`` produces
    byte-identical output. The information is gone by the time the log is
    written. We resolve it as "absent", which is correct in essentially every
    real case, and accept that a request deliberately crafted with a ``-``
    User-Agent will be recorded as having none.
    """
    if raw in (None, "-", ""):
        return None
    return raw


class LogFormatParser:
    """Parses lines of one Apache-style log format.

    Instances are immutable and hold a compiled regex, so a single parser can be
    shared across ingest workers.
    """

    def __init__(self, log_format: str, name: str = "custom") -> None:
        self.name = name
        self.log_format = log_format
        self._compiled = _compile(log_format)

    @property
    def pattern(self) -> re.Pattern[str]:
        """The compiled regex, the widened reading. Exposed for diagnostics and
        tests; a line it refuses may still be read by the plain one (see
        `_CompiledFormat.fallback`)."""
        return self._compiled.pattern

    def is_metadata(self, line: str) -> bool:
        """An Apache log has no bookkeeping lines: every line is a request."""
        del line
        return False

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        """Parse one line, or return `None` if it does not fit this format.

        `None` means "this line is not in this format" — the caller quarantines
        it. Lines that *are* in the format but have unusable individual fields
        are still returned, with those fields absent.
        """
        compiled = self._compiled
        match = compiled.pattern.match(line)
        if match is None and compiled.fallback is not None:
            match = compiled.fallback.match(line)
        if match is None:
            return None

        slots = compiled.slots
        # The groups the regex engine already has, plus one `None` past the end
        # so a field this format does not write reads as absent without a
        # branch. This replaced `groupdict()` and the sixteen dictionary lookups
        # a line was then read back through — the same information, without
        # building a dictionary per line to hold it.
        values: Sequence[str | None] = match.groups() + _NOTHING

        # Apache escapes `"` and `\` inside quoted fields and writes control
        # bytes as `\xHH`; a payload hidden behind that would slip past every
        # signature, so it is undone before anything reads it. One scan of the
        # whole line decides whether any of that is needed, and on ordinary
        # traffic it is not — so the copy below is usually skipped entirely.
        if compiled.quoted_slots and "\\" in line:
            unescaped = list(values)
            for index in compiled.quoted_slots:
                text = unescaped[index]
                if text is not None and "\\" in text:
                    unescaped[index] = _unescape(text)
            values = unescaped

        timestamp = (
            _parse_custom_timestamp(values[slots.time], compiled.time_format)
            if compiled.time_format is not None
            else _parse_timestamp(values[slots.time])
        )
        if timestamp is None:
            return None

        client_ip = _clean(values[slots.client_ip]) or _clean(values[slots.remote_host])
        if client_ip is None:
            return None

        # Reads from `values`, so a quoted field here is already unescaped.
        extra = {
            name: text
            for name, index in compiled.extra_slots
            if (text := values[index]) and text != "-"
        }

        method = _clean(values[slots.method])
        path = _clean(values[slots.url_path])
        query = _clean(values[slots.query_string])
        protocol = _clean(values[slots.protocol])

        if (request_line := _clean(values[slots.request_line])) is not None:
            method, path, query, protocol = split_request_line(request_line)
            if method is None:
                extra["malformed_request_line"] = request_line
        elif path is not None and query is None and "?" in path:
            # `%U%q` side by side, where the path's run of non-blanks takes the
            # query too, or nginx's `$request_uri`, which is both. Split where a
            # request line is split, as `parsers.base.read_target` does.
            path, _separator, query = path.partition("?")

        return NormalizedEvent(
            timestamp=timestamp,
            client_ip=client_ip,
            evidence=ref,
            method=method,
            path=path,
            query=query.lstrip("?") if query else None,
            protocol=protocol,
            status=_as_int(values[slots.status]),
            bytes_sent=_as_int(values[slots.bytes_clf] or values[slots.bytes_sent]),
            referer=_clean(values[slots.referer]),
            user_agent=_clean(values[slots.user_agent]),
            host=_clean(values[slots.server_name]),
            extra=extra,
        )
