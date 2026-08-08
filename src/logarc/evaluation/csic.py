"""Reading the CSIC 2010 HTTP dataset into an access log.

CSIC 2010 is a public corpus of HTTP requests against a web shop, split into a
normal set and an anomalous one. It is the standard reference for this kind of
work, so results on it are comparable with published numbers, which results on
generated traffic never are.

It is not an access log, and converting it exposes three things that have to be
stated rather than smoothed over:

**There are no responses.** The traces are requests only. Status is therefore
synthesised as 200 and response size left absent, which means outcome — the
attempt-versus-breach distinction that the reconstruction is built around —
cannot be measured on this dataset at all.

**There are no addresses.** Per-IP reconstruction needs clients, so each
distinct `JSESSIONID` is given an address of its own. A session is the closest
thing the traces carry to one person's visit.

**Many of the attacks are in POST bodies.** A web server access log records the
request line and nothing after it, so a payload sent in a body leaves no trace
in one. Bodies are therefore dropped, and the number of attacks that thereby
become invisible is counted and reported — it is a real limit on what any
access-log tool can see, and hiding it by folding bodies into the query string
would mean measuring a tool nobody can deploy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from logarc.core.activity import ActivityCategory
from logarc.evaluation.truth import TruthRecord, TruthWriter

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

__all__ = ["CsicError", "CsicResult", "convert_csic"]

#: The first line of a request, as the traces write it: an absolute URL rather
#: than a path, which is legal in HTTP/1.1 and unusual anywhere else.
_REQUEST_LINE: Final = re.compile(
    r"^(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+(?P<url>\S+)\s+HTTP/1\.[01]$"
)
_SESSION: Final = re.compile(r"JSESSIONID=([0-9A-Za-z]+)")

DEFAULT_START: Final = datetime(2010, 1, 1, 0, 0, tzinfo=UTC)

#: Seconds between consecutive requests in the rebuilt log. The traces carry no
#: timing, so this is a stated fiction rather than a measurement.
DEFAULT_INTERVAL: Final = 3.0

_UNKNOWN_SESSION: Final = "no-session"


class CsicError(ValueError):
    """Raised when a file is not in the CSIC trace format."""


@dataclass(frozen=True, slots=True)
class _Request:
    method: str
    path: str
    query: str
    body: str
    user_agent: str
    session: str
    hostile: bool


@dataclass(frozen=True, slots=True)
class CsicResult:
    """What the conversion produced, and what it had to leave behind."""

    path: Path
    truth_path: Path | None
    requests: int
    normal: int
    anomalous: int
    sessions: int
    attacks_hidden_in_bodies: int
    """Attacks whose payload was only ever in a POST body.

    An access log cannot contain these. Counted so that recall measured on this
    dataset can be read against the ceiling it is actually working under.
    """

    @property
    def visible_attack_ratio(self) -> float:
        if not self.anomalous:
            return 0.0
        return 1.0 - self.attacks_hidden_in_bodies / self.anomalous


def convert_csic(
    *,
    normal: Sequence[Path],
    anomalous: Sequence[Path],
    out: Path,
    truth_path: Path | None = None,
    include_bodies: bool = False,
    start: datetime = DEFAULT_START,
    interval: float = DEFAULT_INTERVAL,
) -> CsicResult:
    """Write the traces as one Apache `combined` log, in the order given."""
    sessions: dict[str, str] = {}
    counts = {"normal": 0, "anomalous": 0, "hidden": 0}
    line_no = 0

    with (
        _open_truth(truth_path, source_file_id=out.name) as truth,
        out.open("wb") as handle,
    ):
        for request in _read_all(normal, anomalous):
            line_no += 1
            counts["anomalous" if request.hostile else "normal"] += 1
            if request.hostile and not request.query and request.body:
                counts["hidden"] += 1

            address = sessions.setdefault(request.session, _address(len(sessions)))
            moment = start + timedelta(seconds=interval * line_no)
            handle.write(_format(request, address, moment, include_bodies).encode("utf-8"))
            handle.write(b"\n")

            if truth is not None:
                truth.write(
                    TruthRecord(
                        line_no=line_no,
                        client_ip=address,
                        category=_category(request.hostile),
                        instance_id=f"{address}#{'attack' if request.hostile else 'normal'}",
                    )
                )

    if not line_no:
        raise CsicError(
            "no HTTP requests found; expected CSIC 2010 trace files, "
            "in which each request begins with a line like "
            "'GET http://host/path HTTP/1.1'"
        )

    return CsicResult(
        path=out,
        truth_path=truth_path,
        requests=line_no,
        normal=counts["normal"],
        anomalous=counts["anomalous"],
        sessions=len(sessions),
        attacks_hidden_in_bodies=counts["hidden"],
    )


def _category(hostile: bool) -> ActivityCategory:
    """A stand-in, because the dataset never says which technique it is.

    The truth file records `binary` granularity alongside these, so scoring
    refuses to report per-category figures derived from them.
    """
    return ActivityCategory.EXPLOITATION if hostile else ActivityCategory.BROWSING


def _read_all(normal: Sequence[Path], anomalous: Sequence[Path]) -> Iterator[_Request]:
    for path in normal:
        yield from _read_file(path, hostile=False)
    for path in anomalous:
        yield from _read_file(path, hostile=True)


def _read_file(path: Path, *, hostile: bool) -> Iterator[_Request]:
    """Parse one trace file.

    Blocks are separated by blank lines, but a POST has a blank line of its own
    between its headers and its body, so the start of a request is found by the
    request line rather than by counting blanks.
    """
    with path.open("r", encoding="utf-8", errors="surrogateescape") as handle:
        pending: list[str] = []
        for raw in handle:
            line = raw.rstrip("\r\n")
            if _REQUEST_LINE.match(line):
                if pending:
                    yield _to_request(pending, hostile=hostile)
                pending = [line]
            elif pending:
                pending.append(line)
        if pending:
            yield _to_request(pending, hostile=hostile)


def _to_request(block: Sequence[str], *, hostile: bool) -> _Request:
    match = _REQUEST_LINE.match(block[0])
    if match is None:  # pragma: no cover - only reached if the caller misuses this
        raise CsicError(f"not a request line: {block[0]!r}")

    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in block[1:]:
        if in_body:
            if line:
                body_lines.append(line)
            continue
        if not line:
            in_body = True
            continue
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()

    path, _, query = _strip_origin(match.group("url")).partition("?")
    cookie = _SESSION.search(headers.get("cookie", ""))

    return _Request(
        method=match.group("method"),
        path=path or "/",
        query=query,
        body="&".join(body_lines),
        user_agent=headers.get("user-agent", "-"),
        session=cookie.group(1) if cookie else _UNKNOWN_SESSION,
        hostile=hostile,
    )


def _strip_origin(url: str) -> str:
    """`http://host:8080/a/b?c` -> `/a/b?c`.

    The traces use the absolute form, which is legal in a request line but not
    what a server writes to its access log.
    """
    for scheme in ("http://", "https://"):
        if url.startswith(scheme):
            _, _, remainder = url[len(scheme) :].partition("/")
            return f"/{remainder}"
    return url


def _address(index: int) -> str:
    """One address per session, from the range reserved for documentation."""
    return f"192.0.2.{index % 254 + 1}" if index < 254 else f"198.51.100.{index % 254 + 1}"


def _format(request: _Request, address: str, moment: datetime, include_bodies: bool) -> str:
    query = request.query
    if include_bodies and request.body:
        query = f"{query}&{request.body}" if query else request.body

    target = f"{request.path}?{query}" if query else request.path
    stamp = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
    # Status and size are inventions: the traces have no responses at all.
    return (
        f'{address} - - [{stamp}] "{request.method} {target} HTTP/1.1" 200 - '
        f'"-" "{request.user_agent}"'
    )


class _NoTruth:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: object) -> None:
        return None


def _open_truth(path: Path | None, *, source_file_id: str) -> TruthWriter | _NoTruth:
    if path is None:
        return _NoTruth()
    return TruthWriter(
        path,
        scenario="csic-2010",
        seed=0,
        source_file_id=source_file_id,
        granularity="binary",
    )
