"""Reads a log laid out as a table: IIS W3C, and CSV.

The third kind, and the one that brings a problem the first two did not have:
**the file declares its own columns.** A W3C log opens with `#Fields: date time
c-ip ...`, and a CSV often names its columns in the first row. So the definition
a reader saves is not the whole answer — part of it is in the log.

That is settled before anything reads a line, by `ColumnsFormatSpec.resolved`,
in the process that opened the file. What travels to an ingest worker and into
the case is the resolved definition, with the columns it actually found written
down. A worker handed a byte range halfway through a file has never seen the
header and could not have worked them out; and a case that recorded "the
columns are in the file" would depend, a year later, on a file nobody kept.

The parser itself stays immutable, which is what the `LogParser` contract asks
for. It follows that a log which *redeclares* its fields part-way through —
W3C permits this — is quarantined from that point rather than misread from it:
a row whose column count does not match is refused. Read by position against
the wrong count, every field after the missing one is somebody else's value,
and nothing downstream would notice.
"""

from __future__ import annotations

import csv
from typing import TYPE_CHECKING, Final

from logarc.core.event import NormalizedEvent
from logarc.parsers.fieldnames import JOIN, MAPPABLE, REQUIRED
from logarc.parsers.times import TimeFormatError, check_time_format, read_time

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.evidence import EvidenceRef

__all__ = [
    "FIELDS_DIRECTIVE",
    "MAPPABLE",
    "ColumnsFormatError",
    "ColumnsParser",
    "check_mapping",
    "declared_columns",
]


class ColumnsFormatError(ValueError):
    """Raised when a table format's columns or mapping cannot be used."""


#: How W3C names its columns. Everything else in the header is `#Software`,
#: `#Version`, `#Date` and the like, which say nothing about the layout.
FIELDS_DIRECTIVE: Final = "#Fields:"


def check_mapping(mapping: Sequence[tuple[str, str]]) -> None:
    """Refuse a mapping that is wrong however the columns turn out.

    Separate from building a parser because a table format may not know its
    columns yet — a W3C log declares them, so the definition is complete only
    once a file is in hand. This is everything that can be judged before then,
    and the library uses it to refuse a saved format that could never work.
    """
    unknown = [ours for ours, _theirs in mapping if ours not in MAPPABLE]
    if unknown:
        raise ColumnsFormatError(
            f"{', '.join(repr(item) for item in unknown)} is not a field logarc "
            f"records; it reads: {', '.join(MAPPABLE)}"
        )
    absent = [field for field in REQUIRED if field not in dict(mapping)]
    if absent:
        raise ColumnsFormatError(
            f"a table format needs {' and '.join(REQUIRED)} mapped to a column; "
            f"{', '.join(absent)} is not"
        )


def split_row(line: str, separator: str) -> list[str]:
    """One row into its cells.

    Through `csv` rather than `str.split`, so a comma-separated field holding a
    comma inside quotes comes back whole. W3C quotes nothing, so this costs
    those logs nothing.
    """
    return next(csv.reader([line], delimiter=separator, skipinitialspace=False), [])


def declared_columns(lines: Sequence[str], separator: str) -> tuple[tuple[str, ...], str]:
    """The column names a file declares, and the row that declared them.

    A `#Fields:` directive first, because a W3C log has one and it is
    unambiguous; the row is then empty, since no line of data was consumed.
    Failing that, the first row that is not a directive — a header in a CSV
    that has one, and the first row of *data* in a CSV that does not. That
    second case is caught by the mapping not matching, loudly and before any
    ingest, so guessing wrongly here cannot pass silently.

    The row comes back because the parser has to know not to read it as data,
    and it is compared as text: a worker given a byte range does not know which
    line it started at, so a line number would mean nothing to it.
    """
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(FIELDS_DIRECTIVE):
            return tuple(stripped[len(FIELDS_DIRECTIVE) :].split()), ""
        if stripped.startswith("#"):
            continue
        return tuple(cell.strip() for cell in split_row(stripped, separator)), stripped
    return (), ""


def _clean(raw: str | None) -> str | None:
    """A cell as a field, treating `-` and empty as absent, as W3C writes them."""
    if raw is None:
        return None
    text = raw.strip()
    return None if text in ("", "-") else text


def _as_int(raw: str | None) -> int | None:
    text = _clean(raw)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _split_request_line(raw: str) -> tuple[str | None, str | None, str | None, str | None]:
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


class ColumnsParser:
    """Parses rows of one table-shaped log.

    Immutable after construction, holding the column names it was resolved
    with, so a single parser can be shared across ingest workers.
    """

    def __init__(
        self,
        columns: Sequence[str],
        mapping: Sequence[tuple[str, str]],
        *,
        name: str = "columns",
        separator: str = " ",
        time_format: str = "",
        header_row: str = "",
    ) -> None:
        check_mapping(mapping)
        if not columns:
            raise ColumnsFormatError(
                f"format {name!r} does not know its columns: none were given, and none "
                "were declared in the log"
            )

        self._index = {column: position for position, column in enumerate(columns)}
        # Only the columns without which there is no event have to be there.
        # IIS logs whatever fields the administrator ticked, so a format written
        # for a family names more columns than any one file carries — a referer
        # that is absent is not an error, it is a log without referers. A field
        # the reader misspells shows as empty in the preview, which is where
        # they are looking; a misspelt *time* would show as nothing readable at
        # all, so that one is refused here.
        missing = sorted(
            {
                theirs
                for ours, spec in mapping
                if ours in REQUIRED
                for theirs in spec.split(JOIN)
                if theirs not in self._index
            }
        )
        if missing:
            raise ColumnsFormatError(
                f"the log has no column called {', '.join(repr(item) for item in missing)}; "
                f"it has: {', '.join(columns)}"
            )

        self._mapping = dict(mapping)
        try:
            check_time_format(time_format)
        except TimeFormatError as exc:
            raise ColumnsFormatError(str(exc)) from exc

        self.name = name
        self._columns = tuple(columns)
        self._separator = separator
        self._time_format = time_format
        self._claimed = {theirs for _ours, spec in mapping for theirs in spec.split(JOIN)}
        # The row that named the columns, when they came from one. Compared as
        # text rather than remembered as a line number, because a worker given
        # a byte range does not know which line it started at.
        self._header_row = header_row.strip()

    def is_metadata(self, line: str) -> bool:
        """Whether this line is the log's own bookkeeping rather than a request.

        Four directives open every IIS file, and a CSV with a header has one
        more. Quarantined, they would put a "lines could not be parsed" strip
        over every table-shaped case ever opened — which is the notice that
        exists to mean something went wrong.
        """
        stripped = line.strip()
        return stripped.startswith("#") or (bool(self._header_row) and stripped == self._header_row)

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        """Parse one row, or return `None` if it is not a row of this table."""
        if not line.strip() or self.is_metadata(line):
            return None

        cells = split_row(line.rstrip("\r\n"), self._separator)
        if len(cells) != len(self._columns):
            # Read by position against the wrong count, every field after the
            # missing one is somebody else's value. Refused loudly instead.
            return None

        def cell(field: str) -> str | None:
            spec = self._mapping.get(field)
            if spec is None:
                return None
            wanted = [self._index[theirs] for theirs in spec.split(JOIN) if theirs in self._index]
            if not wanted:
                return None
            return " ".join(cells[position].strip() for position in wanted)

        timestamp = read_time(cell("timestamp"), self._time_format)
        if timestamp is None:
            return None
        client_ip = _clean(cell("client_ip"))
        if client_ip is None:
            return None

        method = _clean(cell("method"))
        path = _clean(cell("path"))
        query = _clean(cell("query"))
        protocol = _clean(cell("protocol"))

        extra = {
            column: text
            for column, position in self._index.items()
            if column not in self._claimed and (text := _clean(cells[position])) is not None
        }

        if (request_line := _clean(cell("request_line"))) is not None:
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
            status=_as_int(cell("status")),
            bytes_sent=_as_int(cell("bytes_sent")),
            referer=_clean(cell("referer")),
            user_agent=_clean(cell("user_agent")),
            host=_clean(cell("host")),
            extra=extra,
        )
