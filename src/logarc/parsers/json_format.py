"""Reads a log that writes one JSON object per line.

The second kind of format, and it works the other way round from a `LogFormat`
directive: names rather than positions. That is what makes it the test of
whether the record shape from the first kind was general enough — nothing here
can lean on a format being a directive string.

What a JSON log does *not* tell us is which of its keys is the client address,
because every product spells it differently. So a format of this kind is a
mapping: our field name to theirs. `guess_mapping` proposes one from a sample
line, which is worth doing here and is not worth doing for a positional format
— JSON keys are self-describing, `%h` and `%v` are not. The proposal is shown
before it is saved, because a wrong guess is worse than no guess: the reader
accepts it and finds out at ingest, when every line has been quarantined.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from logarc.core.event import NormalizedEvent

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

    from logarc.core.evidence import EvidenceRef

__all__ = [
    "MAPPABLE",
    "JsonFormatError",
    "JsonParser",
    "flatten",
    "guess_mapping",
]


class JsonFormatError(ValueError):
    """Raised when a JSON format's mapping cannot be used."""


#: Every field of ours a JSON key may be mapped to. `request_line` is here for
#: the logs that write `GET /a HTTP/1.1` whole; it is split into method, path,
#: query and protocol exactly as `%r` is, so the same traffic reconstructs the
#: same way whichever kind of format read it.
MAPPABLE: Final[tuple[str, ...]] = (
    "timestamp",
    "client_ip",
    "request_line",
    "method",
    "path",
    "query",
    "protocol",
    "status",
    "bytes_sent",
    "referer",
    "user_agent",
    "host",
)

#: Without these there is no event: everything downstream is ordered by time
#: and grouped by address. The directive compiler refuses a line missing either
#: for the same reason; this refuses the *format*, which is earlier and kinder.
REQUIRED: Final[tuple[str, ...]] = ("timestamp", "client_ip")

#: Key names seen in the wild, per field of ours, best first. Used only by
#: `guess_mapping`; a saved format holds the reader's own answer.
_CANDIDATES: Final[dict[str, tuple[str, ...]]] = {
    "timestamp": ("time", "timestamp", "@timestamp", "ts", "time_local", "time_iso8601",
                  "eventtime", "start_time", "date"),
    "client_ip": ("remote_addr", "client_ip", "clientip", "remote_ip", "src_ip", "c_ip",
                  "source_ip", "ip"),
    "request_line": ("request", "request_line"),
    "method": ("request_method", "method", "http_method", "verb", "cs_method"),
    "path": ("request_uri", "uri", "path", "url", "cs_uri_stem", "http_path"),
    "query": ("query_string", "query", "args", "cs_uri_query"),
    "protocol": ("server_protocol", "protocol", "http_version"),
    "status": ("status", "status_code", "response_status", "sc_status", "http_status", "code"),
    "bytes_sent": ("body_bytes_sent", "bytes_sent", "response_size", "sc_bytes", "bytes",
                   "size", "content_length"),
    "referer": ("http_referer", "referer", "referrer", "cs_referer"),
    "user_agent": ("http_user_agent", "user_agent", "useragent", "cs_user_agent", "agent"),
    "host": ("http_host", "host", "server_name", "vhost", "domain"),
}  # fmt: skip

#: Tried in turn when no time format was given. `fromisoformat` covers most of
#: ISO 8601 on the versions this project supports; these are the spellings it
#: does not, and they are common enough to be worth the two extra attempts.
_TIME_FALLBACKS: Final[tuple[str, ...]] = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S",
)

#: Above this, a number is milliseconds rather than seconds. 1e11 seconds is
#: the year 5138 and 1e11 milliseconds is 1973, so nothing real is ambiguous —
#: and read as seconds a millisecond stamp lands in the year 56000 and sorts
#: last for ever without anything downstream questioning it.
_MILLIS_ABOVE: Final = 1e11
_MICROS_ABOVE: Final = 1e14


def flatten(payload: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Every leaf of `payload`, keyed by its dotted path.

    Gateways routinely nest, and a reader should not have to pre-process their
    own evidence before logarc will look at it.
    """
    for key, value in payload.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from flatten(value, f"{path}.")
        else:
            yield path, value


#: Leaf names that name a shape rather than a field. ECS and everything that
#: copies it writes `user_agent.original` and `url.original`, where the leaf
#: says nothing and the parent says all of it — so a path ending in one of
#: these is also offered under its parent's name.
_GENERIC_LEAVES: Final[frozenset[str]] = frozenset(
    {"original", "value", "text", "raw", "full", "name", "address"}
)


def _spellings(path: str) -> Iterator[str]:
    """The names a path might be recognised under, most specific first."""
    leaf = path.rsplit(".", 1)[-1].lower()
    yield path.lower().replace(".", "_").lstrip("@_")
    yield leaf
    if leaf in _GENERIC_LEAVES and "." in path:
        yield path.rsplit(".", 2)[-2].lower()


def guess_mapping(sample: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Propose a mapping from one sample line, for the reader to correct.

    A key nothing recognises is left out rather than guessed at. The reader is
    shown what this proposed and can see the gap; a wrong guess they accept is
    the failure this is trying to prevent, not the one it would cause.
    """
    known: dict[str, str] = {}
    for path in dict(flatten(sample)):
        for spelling in _spellings(path):
            known.setdefault(spelling, path)

    mapping: list[tuple[str, str]] = []
    taken: set[str] = set()
    for ours, candidates in _CANDIDATES.items():
        for candidate in candidates:
            found = known.get(candidate)
            if found is not None and found not in taken:
                mapping.append((ours, found))
                taken.add(found)
                break
    return tuple(mapping)


def _as_text(value: Any) -> str | None:
    """One JSON value as a field, treating `-` and empty as absent.

    `-` because a log that was a text log yesterday keeps writing Apache's
    placeholder after being turned into a JSON one, which is most of them.
    """
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return None if text in ("", "-") else text


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):  # bool is an int, and never a byte count
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _from_epoch(number: float) -> datetime:
    if abs(number) > _MICROS_ABOVE:
        number /= 1_000_000
    elif abs(number) > _MILLIS_ABOVE:
        number /= 1000
    return datetime.fromtimestamp(number, tz=UTC)


def _in_utc(parsed: datetime) -> datetime:
    """A stamp carrying no offset is read as UTC.

    Reading it in the machine's own zone would make one log parse to different
    instants on two machines, and a case may not do that.
    """
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)


def _time_told(text: str, time_format: str) -> datetime | None:
    """Read a stamp with the pattern the format was given. No second guesses:
    the reader said what this field is, and quietly reading it some other way
    would make the pattern they wrote look right when it is not."""
    try:
        return _in_utc(datetime.strptime(text, time_format))
    except ValueError:
        return None


def _time_guessed(text: str) -> datetime | None:
    """Read a stamp the format did not describe: ISO first, then epoch."""
    # `Z` spelled out, because `fromisoformat` did not accept it before 3.12
    # and this project supports 3.11.
    candidate = f"{text[:-1]}+00:00" if text.endswith(("Z", "z")) else text
    try:
        return _in_utc(datetime.fromisoformat(candidate))
    except ValueError:
        pass
    for fmt in _TIME_FALLBACKS:
        try:
            return _in_utc(datetime.strptime(candidate, fmt))
        except ValueError:
            continue
    number = _as_number(text)
    return _from_epoch(number) if number is not None else None


def _read_time(value: Any, time_format: str) -> datetime | None:
    """The timestamp, or `None` if this value is not one."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(value)

    text = str(value).strip()
    if not text:
        return None
    return _time_told(text, time_format) if time_format else _time_guessed(text)


def _as_number(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _split_request_line(raw: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Split `GET /a?b=c HTTP/1.1`, the same way the directive compiler does.

    Duplicated deliberately rather than imported: the two compilers share no
    other code, and the day one of them needs to treat a malformed line
    differently, an import would make that a change to both.
    """
    parts = raw.split(" ")
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        method, protocol = parts[0], parts[-1]
        target = " ".join(parts[1:-1])
    elif len(parts) == 2:
        method, target, protocol = parts[0], parts[1], None
    else:
        return None, None, None, None

    path, separator, query = target.partition("?")
    return method, path, (query if separator else None), protocol


class JsonParser:
    """Parses lines of one JSON log format.

    Immutable after construction and holding only strings, so a single parser
    can be shared across ingest workers.
    """

    def __init__(
        self, mapping: Sequence[tuple[str, str]], *, name: str = "json", time_format: str = ""
    ) -> None:
        unknown = [ours for ours, _theirs in mapping if ours not in MAPPABLE]
        if unknown:
            known = ", ".join(MAPPABLE)
            raise JsonFormatError(
                f"{', '.join(repr(item) for item in unknown)} is not a field logarc "
                f"records; it reads: {known}"
            )
        self._mapping = dict(mapping)
        missing = [field for field in REQUIRED if field not in self._mapping]
        if missing:
            raise JsonFormatError(
                f"a JSON format needs {' and '.join(REQUIRED)} mapped to a key; "
                f"{', '.join(missing)} is not"
            )
        self.name = name
        self._time_format = time_format
        self._mapped_keys = set(self._mapping.values())

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        """Parse one line, or return `None` if it is not a line of this log."""
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(payload, dict):
            # Valid JSON and not a log line. Accepting it would let this format
            # score well against a file of anything at all, and auto-detection
            # would then offer it for logs it cannot read.
            return None

        leaves = dict(flatten(payload))

        timestamp = _read_time(leaves.get(self._mapping["timestamp"]), self._time_format)
        if timestamp is None:
            return None
        client_ip = _as_text(leaves.get(self._mapping["client_ip"]))
        if client_ip is None:
            return None

        def mapped(field: str) -> Any:
            key = self._mapping.get(field)
            return leaves.get(key) if key is not None else None

        method = _as_text(mapped("method"))
        path = _as_text(mapped("path"))
        query = _as_text(mapped("query"))
        protocol = _as_text(mapped("protocol"))

        extra = {
            key: text
            for key, value in leaves.items()
            if key not in self._mapped_keys and (text := _as_text(value)) is not None
        }

        if (request_line := _as_text(mapped("request_line"))) is not None:
            method, path, query, protocol = _split_request_line(request_line)
            if method is None:
                extra["malformed_request_line"] = request_line

        return NormalizedEvent(
            timestamp=timestamp,
            client_ip=client_ip,
            evidence=ref,
            method=method,
            path=path,
            query=query.lstrip("?") if query else None,
            protocol=protocol,
            status=_as_int(mapped("status")),
            bytes_sent=_as_int(mapped("bytes_sent")),
            referer=_as_text(mapped("referer")),
            user_agent=_as_text(mapped("user_agent")),
            host=_as_text(mapped("host")),
            extra=extra,
        )
