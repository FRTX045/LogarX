"""Reads a log that writes one JSON object per line.

The second kind of format, and it works the other way round from a `LogFormat`
directive: names rather than positions. That is what makes it the test of
whether the record shape from the first kind was general enough — nothing here
can lean on a format being a directive string.

What a JSON log does *not* tell us is which of its keys is the client address,
because every product spells it differently. So a format of this kind is a
mapping: our field name to theirs. All this module contributes to guessing one
is where the names are — the dotted path of every leaf. What the names *mean*
is shared with the table kind in `parsers.fieldnames`: `remote_addr` here and
`c-ip` there are the same field, and a candidate list per kind would drift.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from logarx.core.event import NormalizedEvent
from logarx.parsers.base import read_target, split_client, split_request_line
from logarx.parsers.fieldnames import MAPPABLE, REQUIRED, recorded_by
from logarx.parsers.fieldnames import guess_mapping as guess_from_names
from logarx.parsers.times import TimeFormatError, check_time_format, read_time

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

    from logarx.core.evidence import EvidenceRef

__all__ = ["JsonFormatError", "JsonParser", "flatten", "guess_mapping"]


class JsonFormatError(ValueError):
    """Raised when a JSON format's mapping cannot be used."""


def flatten(payload: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Every leaf of `payload`, keyed by its dotted path.

    Gateways routinely nest, and a reader should not have to pre-process their
    own evidence before LogarX will look at it.
    """
    for key, value in payload.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from flatten(value, f"{path}.")
        else:
            yield path, value


def guess_mapping(sample: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Propose a mapping from one sample line, for the reader to correct."""
    return guess_from_names([path for path, _value in flatten(sample)])


def _as_text(value: Any) -> str | None:
    """One JSON value as a field, treating `-` and empty as absent.

    `-` because a log that was a text log yesterday keeps writing Apache's
    placeholder after being turned into a JSON one, which is most of them.

    A one-element list is unwrapped, because that is how a header is spelled
    where headers may repeat: Caddy writes `"User-Agent": ["curl/8.4.0"]`.
    Rendered whole it reaches the evidence table as `['curl/8.4.0']`, brackets
    and quotes and all, and every rule that reads a user agent then sees a
    string no client ever sent. A list of two or more is left alone — there
    really were two values, and picking one would be inventing an answer.
    """
    if value is None:
        return None
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
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
                f"{', '.join(repr(item) for item in unknown)} is not a field LogarX "
                f"records; it reads: {known}"
            )
        self._mapping = dict(mapping)
        missing = [field for field in REQUIRED if field not in self._mapping]
        if missing:
            raise JsonFormatError(
                f"a JSON format needs {' and '.join(REQUIRED)} mapped to a key; "
                f"{', '.join(missing)} is not"
            )
        try:
            check_time_format(time_format)
        except TimeFormatError as exc:
            raise JsonFormatError(str(exc)) from exc

        self.name = name
        self.records = recorded_by(self._mapping)
        self._time_format = time_format
        self._mapped_keys = set(self._mapping.values())

    def is_metadata(self, line: str) -> bool:
        """A JSON log has no bookkeeping lines: every line is an object."""
        del line
        return False

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        """Parse one line, or return `None` if it is not a line of this log."""
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError):
            # `RecursionError` is not a `ValueError`, so it used to travel out
            # of here untouched and end the whole ingest. It is raised by a line
            # nested deeper than Python will decode — twenty thousand `[` will
            # do it — and detection scores every registered parser against the
            # sample, so one such line stopped a case being made at all,
            # whatever kind of log the file actually was.
            #
            # A line this tool cannot decode is a line that is not of this
            # format, which is what `None` means here. Refusing it puts the
            # line into the quarantine record, where a line too damaged to read
            # is supposed to be counted rather than fatal.
            return None
        if not isinstance(payload, dict):
            # Valid JSON and not a log line. Accepting it would let this format
            # score well against a file of anything at all, and auto-detection
            # would then offer it for logs it cannot read.
            return None

        leaves = dict(flatten(payload))

        timestamp = read_time(leaves.get(self._mapping["timestamp"]), self._time_format)
        if timestamp is None:
            return None
        written = _as_text(leaves.get(self._mapping["client_ip"]))
        if written is None:
            return None
        client_ip, client_port = split_client(written)

        def mapped(field: str) -> Any:
            key = self._mapping.get(field)
            return leaves.get(key) if key is not None else None

        method = _as_text(mapped("method"))
        protocol = _as_text(mapped("protocol"))
        path, query, host = read_target(
            _as_text(mapped("path")),
            _as_text(mapped("query")),
            _as_text(mapped("url")),
            _as_text(mapped("host")),
        )

        extra = {
            key: text
            for key, value in leaves.items()
            if key not in self._mapped_keys and (text := _as_text(value)) is not None
        }
        if client_port is not None:
            extra.setdefault("client_port", client_port)

        if (request_line := _as_text(mapped("request_line"))) is not None:
            method, path, query, protocol = split_request_line(request_line)
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
            host=host,
            extra=extra,
        )
