"""Tests for the ingest pipeline."""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.ingest.pipeline import (
    PROGRESS_STRIDE,
    FormatDetectionError,
    IngestCancelled,
    ingest_file,
)
from logarx.ingest.quarantine import Quarantine
from logarx.parsers.registry import get_parser, register_format, unregister_format
from logarx.storage.event_store import ParquetEventStore

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /a HTTP/1.1" 404 0 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.0"',
]


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def case(tmp_path: Path) -> Path:
    return tmp_path / "case"


def test_events_land_in_the_store_and_can_be_read_back(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(log, store, quarantine)
    store.finalize()

    assert [e.path for e in store.events_for_ip("203.0.113.5")] == ["/", "/a"]


def test_result_reports_what_happened(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine)

    assert result.lines_read == 3
    assert result.events_parsed == 3
    assert result.lines_quarantined == 0
    assert result.log_format == "apache-combined"
    assert len(result.sha256) == 64


def test_unparseable_lines_are_quarantined_rather_than_dropped(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join([*LINES, "<<< truncated write >>>"]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)
        assert quarantine.count == 1

    assert result.events_parsed == 3
    assert result.lines_quarantined == 1


def test_a_line_longer_than_the_limit_is_quarantined_rather_than_parsed(
    tmp_path: Path, case: Path
) -> None:
    """Parsing one costs 327 times its own length in memory.

    Measured while auditing the tool as a target: a 16 MB line held 5.5 GB and
    a 64 MB line held 20.9 GB. The parse is linear — the multiplier is simply
    enormous — and nothing bounded either the line or the gzip ratio that can
    deliver it, so a ~64 KB archive could ask for 21 GB.

    The line is still counted and still recorded. It is evidence that something
    wrote a line no server would write, which is worth more than the bytes.
    """
    path = tmp_path / "access.log"
    huge = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /'
        + "a" * 200_000
        + ' HTTP/1.1" 200 1 "-" "x"'
    )
    path.write_text("\n".join([*LINES, huge]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine, max_line_bytes=50_000)

    assert result.events_parsed == 3, "the ordinary lines are still read"
    assert result.lines_quarantined == 1
    assert result.lines_read == 4, "and the long line is counted, not skipped"


def test_the_line_limit_can_be_raised_for_a_log_that_needs_it(tmp_path: Path, case: Path) -> None:
    """The bound is a default, not a judgement about what a log may contain."""
    path = tmp_path / "access.log"
    long_line = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /'
        + "a" * 20_000
        + ' HTTP/1.1" 200 1 "-" "x"'
    )
    path.write_text("\n".join([*LINES, long_line]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine, max_line_bytes=100_000)

    assert result.events_parsed == 4
    assert result.lines_quarantined == 0


def test_an_over_long_line_is_kept_out_of_the_detection_sample(tmp_path: Path, case: Path) -> None:
    """Detection is the other place a huge line gets parsed, and the earlier one.

    `resolve_format` scores every registered parser against the first two
    hundred lines. A line excluded from parsing but left in that sample would
    still be handed to every parser in the registry, so the bound would save
    nothing on the path that runs first.
    """
    path = tmp_path / "access.log"
    huge = "{" + "a" * 400_000 + "}"
    path.write_text(huge + "\n" + "\n".join(LINES) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine, max_line_bytes=50_000)

    assert result.events_parsed == 3, "the format is still detected from the rest"
    assert result.lines_quarantined == 1


def test_blank_lines_are_ignored_without_being_treated_as_damage(
    tmp_path: Path, case: Path
) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join([LINES[0], "", "   ", LINES[1]]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)

    assert result.events_parsed == 2
    assert result.lines_quarantined == 0


def test_format_is_detected_when_not_specified(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine)

    assert result.log_format == "apache-combined"


def test_a_cancelled_ingest_stops_reading_and_says_how_far_it_got(
    tmp_path: Path, case: Path
) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES * 10) + "\n", encoding="utf-8")
    store = ParquetEventStore(case)
    checks = 0

    def stop() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 2

    with (
        Quarantine(case) as quarantine,
        pytest.raises(IngestCancelled) as raised,
    ):
        ingest_file(path, store, quarantine, batch_size=5, should_cancel=stop)

    assert raised.value.lines_read == 10
    assert "cancelled" in str(raised.value)


def test_what_was_read_before_a_cancel_is_kept(tmp_path: Path, case: Path) -> None:
    """A stopped ingest is short, not void: the batches already written are
    evidence, and discarding them would make a cancel destructive."""
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES * 10) + "\n", encoding="utf-8")
    store = ParquetEventStore(case)

    with Quarantine(case) as quarantine, pytest.raises(IngestCancelled):
        ingest_file(path, store, quarantine, batch_size=5, should_cancel=lambda: True)
    store.finalize()

    kept = store.events_for_ip("203.0.113.5")
    assert kept
    assert max(event.evidence.line_no for event in kept) <= 5


def test_an_explicit_format_overrides_detection(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine, log_format="apache-common")

    # `common` cannot match combined lines, so every line is quarantined rather
    # than silently mis-parsed.
    assert result.log_format == "apache-common"
    assert result.events_parsed == 0
    assert result.lines_quarantined == 3


def test_undetectable_format_fails_loudly(tmp_path: Path, case: Path) -> None:
    """Guessing wrong would quarantine the whole log and look like an empty
    result, which is worse than refusing."""
    path = tmp_path / "not-a-log.txt"
    path.write_text("hello\nworld\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine, pytest.raises(FormatDetectionError, match="not-a-log"):
        ingest_file(path, store, quarantine)


def test_compressed_logs_ingest_the_same_way(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "access.log.gz"
    path.write_bytes(gzip.compress(("\n".join(LINES) + "\n").encode()))

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)
    store.finalize()

    assert result.events_parsed == 3
    assert result.compression == "gzip"
    assert len(store.events_for_ip("198.51.100.9")) == 1


def test_events_are_written_in_batches_so_memory_stays_bounded(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "big.log"
    line = LINES[0]
    path.write_text("\n".join([line] * 25) + "\n", encoding="utf-8")

    written: list[int] = []
    store = ParquetEventStore(case)
    original_write = store.write

    def counting_write(events: object) -> None:
        batch = list(events)  # type: ignore[call-overload]
        written.append(len(batch))
        original_write(batch)

    store.write = counting_write  # type: ignore[method-assign]
    with Quarantine(case) as quarantine:
        ingest_file(path, store, quarantine, batch_size=10)

    assert written == [10, 10, 5]


def test_evidence_references_point_at_the_original_line_numbers(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join(["#comment", *LINES]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(path, store, quarantine)
    store.finalize()

    events = store.events_for_ip("203.0.113.5")

    # The comment is line 1, so the first real event is line 2.
    assert [e.evidence.line_no for e in events] == [2, 3]


def test_progress_is_reported_while_reading(log: Path, case: Path) -> None:
    seen: list[int] = []
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(
            log, store, quarantine, batch_size=1, on_progress=lambda done, _: seen.append(done)
        )

    assert seen == [1, 2, 3]


def test_progress_is_reported_far_more_often_than_batches_are_written(
    tmp_path: Path, case: Path
) -> None:
    """A batch is a hundred thousand lines, and reporting only when one is
    written meant the window heard once every few seconds — measured at one
    update per 2.7s on a real ingest, which is what made it look stuck.

    The stride is a line count rather than a clock, so this can be asserted
    exactly rather than by waiting and hoping.
    """
    line = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    log = tmp_path / "many.log"
    log.write_text("\n".join([line] * 20_000) + "\n", encoding="utf-8")

    seen: list[int] = []
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine, on_progress=lambda done, _: seen.append(done))
    store.close()

    assert result.lines_read == 20_000
    # One batch would have been written, so the old code reported once.
    assert len(seen) >= 10, f"only {len(seen)} reports for 20,000 lines"
    assert seen == sorted(seen), "the count went backwards"
    assert seen[-1] == 20_000, "the last report is the whole file"


def test_a_progress_report_is_not_sent_twice_for_the_same_line(tmp_path: Path, case: Path) -> None:
    """The stride and the batch boundary can land on the same line. Reporting
    from both would send that line's figures twice, and a rate worked out from
    two reports an instant apart is a division by very nearly nothing."""
    line = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    log = tmp_path / "aligned.log"
    log.write_text("\n".join([line] * 8_000) + "\n", encoding="utf-8")

    seen: list[int] = []
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        # A batch size that is a multiple of the stride, so every batch
        # boundary is also a stride boundary.
        ingest_file(
            log, store, quarantine, batch_size=4_000, on_progress=lambda done, _: seen.append(done)
        )
    store.close()

    assert len(seen) == len(set(seen)), f"a line reported twice: {seen}"


NEWLINE = chr(10)


def test_the_last_report_is_the_whole_file_even_off_the_stride(tmp_path: Path, case: Path) -> None:
    """A file whose length is not a multiple of the stride, which is almost
    every file. Without a report after the loop the last few thousand lines are
    never announced and the window stops at 99% on a finished read.

    Found by mutation: dropping the final report left the suite green, because
    the test beside this one happened to use a round twenty thousand lines.
    """
    line = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    lines = 20_500
    assert lines % PROGRESS_STRIDE, "premise: the file does not end on a stride boundary"
    log = tmp_path / "ragged.log"
    log.write_text(NEWLINE.join([line] * lines) + NEWLINE, encoding="utf-8")

    seen: list[int] = []
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(log, store, quarantine, on_progress=lambda done, _: seen.append(done))
    store.close()

    assert seen[-1] == lines, f"the read finished at {seen[-1]} of {lines}"


# -- one line never ends the import ------------------------------------------


class _BuggyParser:
    """Apache combined, with a bug that raises on any line mentioning `/boom`."""

    name = "test-buggy"

    def __init__(self, error: BaseException) -> None:
        self._error = error
        self._inner = get_parser("apache-combined")

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        if "/boom" in line:
            raise self._error
        return self._inner.parse_line(line, ref)


@pytest.fixture
def buggy() -> Iterator[Callable[[BaseException], str]]:
    names: list[str] = []

    def install(error: BaseException) -> str:
        name = f"test-buggy-{len(names)}"
        register_format(name, lambda: _BuggyParser(error))
        names.append(name)
        return name

    yield install
    for name in names:
        unregister_format(name)


def test_a_line_the_parser_raises_on_is_quarantined_and_the_rest_is_read(
    tmp_path: Path, case: Path, buggy: Callable[[BaseException], str]
) -> None:
    """A parser bug used to end the ingest at that line, with nothing stored:
    the whole log lost to one line, which is the cheapest denial of service
    there is against a tool that reads what attackers wrote."""
    path = tmp_path / "access.log"
    crafted = LINES[0].replace("GET / ", "GET /boom ")
    path.write_text(NEWLINE.join([LINES[0], crafted, *LINES[1:]]) + NEWLINE, encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine, log_format=buggy(OverflowError("bug")))
    store.finalize()

    assert (result.events_parsed, result.lines_quarantined) == (3, 1)
    (entry,) = [json.loads(row) for row in quarantine.path.read_text("utf-8").splitlines()]
    assert entry["line_no"] == 2
    assert "OverflowError" in entry["reason"]


def test_running_out_of_memory_still_stops_the_ingest(
    tmp_path: Path, case: Path, buggy: Callable[[BaseException], str]
) -> None:
    """That says the machine is the problem, not the line, and the next line
    would say the same."""
    path = tmp_path / "access.log"
    path.write_text(LINES[0].replace("GET / ", "GET /boom ") + NEWLINE, encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine, pytest.raises(MemoryError):
        ingest_file(path, store, quarantine, log_format=buggy(MemoryError()))


#: One crafted line per kind found while auditing the tool as a target, each of
#: which used to end the import of the log it was in, with nothing stored.
_COMBINED_WIDE = LINES[0].replace(" 200 2326 ", " 99999999999999999999 99999999999999999999 ")
_JSON_GOOD = (
    '{"time_local": "01/May/2024:09:00:4%d +0000", "remote_addr": "203.0.113.5", '
    '"request": "GET /p%d HTTP/1.1", "status": "200", "body_bytes_sent": "12", '
    '"http_referer": "", "http_user_agent": "%s"}'
)
_CADDY_GOOD = (
    '{"level": "info", "ts": %s, "logger": "http.log.access", "msg": "handled request", '
    '"request": {"remote_ip": "203.0.113.5", "method": "GET", "uri": "/p%d", '
    '"proto": "HTTP/1.1", "host": "x", "headers": {}}, "status": 200, "size": 12}'
)
_IIS_HEAD = [
    "#Software: Microsoft Internet Information Services 10.0",
    "#Version: 1.0",
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip"
    " cs(User-Agent) sc-status",
]
_IIS_ROW = "2024-05-01 09:00:4%d 10.0.0.1 GET /p%d - 80 - 203.0.113.5 %s 200"


@pytest.mark.parametrize(
    ("lines", "events"),
    [
        pytest.param([LINES[0], _COMBINED_WIDE, *LINES[1:]], 4, id="integers-past-64-bits"),
        pytest.param(
            [_JSON_GOOD % (n, n, "\\ud800" if n == 1 else "curl/8.0") for n in range(4)],
            4,
            id="lone-surrogate-escape",
        ),
        pytest.param(
            [_CADDY_GOOD % ("1" + "0" * 400 if n == 1 else f"171455404{n}.0", n) for n in range(4)],
            3,
            id="epoch-of-400-digits",
        ),
        pytest.param(
            [
                *_IIS_HEAD,
                *(_IIS_ROW % (n, n, "curl\r/8.0" if n == 1 else "curl") for n in range(4)),
            ],
            4,
            id="bare-carriage-return",
        ),
    ],
)
def test_one_crafted_line_does_not_end_the_import(
    tmp_path: Path, case: Path, lines: list[str], events: int
) -> None:
    path = tmp_path / "crafted.log"
    path.write_bytes((NEWLINE.join(lines) + NEWLINE).encode("utf-8"))

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)
    store.finalize()

    assert result.events_parsed == events
    assert result.events_parsed + result.lines_quarantined == 4
