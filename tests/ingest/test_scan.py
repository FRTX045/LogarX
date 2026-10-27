"""Splitting a log into byte ranges that workers can parse independently.

The property every test here circles is the same one: **a chunked read must
produce exactly what a sequential read produces.** Parallel ingest is only worth
having if it cannot lose, duplicate or renumber a line, and a split that is
subtly wrong looks like a successful ingest — the failure mode this whole file
exists to make impossible.

Line numbers get their own attention because they are the chain of custody.
A worker starting at byte 25,000,000 has no idea it is at line 130,457 unless
the scan tells it, and an `EvidenceRef` pointing at the wrong line is worse than
no reference at all.
"""

from __future__ import annotations

import gc
import hashlib
import warnings
from itertools import pairwise
from pathlib import Path

import pytest

from logarx.ingest.reader import open_log
from logarx.ingest.scan import Chunk, read_range, scan_chunks


def write(path: Path, lines: int, *, trailing_newline: bool = True) -> Path:
    body = "\n".join(f"line {n} with some padding to give it length" for n in range(1, lines + 1))
    path.write_text(body + ("\n" if trailing_newline else ""), encoding="utf-8")
    return path


def sequential(path: Path) -> list[tuple[int, str]]:
    with open_log(path) as stream:
        return list(stream)


def chunked(path: Path, result: object) -> list[tuple[int, str]]:
    pairs: list[tuple[int, str]] = []
    for chunk in result.chunks:  # type: ignore[attr-defined]
        pairs.extend(read_range(path, chunk))
    return pairs


@pytest.mark.parametrize("parts", [1, 2, 3, 4, 8, 16])
def test_a_chunked_read_reproduces_a_sequential_one(tmp_path: Path, parts: int) -> None:
    """The whole feature in one assertion. Same lines, same numbers, same order."""
    log = write(tmp_path / "access.log", 500)

    result = scan_chunks(log, parts=parts)

    assert chunked(log, result) == sequential(log)


def test_a_file_without_a_trailing_newline_keeps_its_last_line(tmp_path: Path) -> None:
    """Logs get truncated mid-write. Dropping the partial last line would lose
    evidence silently, which is the one outcome quarantine exists to prevent."""
    log = write(tmp_path / "access.log", 50, trailing_newline=False)

    result = scan_chunks(log, parts=4)

    assert chunked(log, result) == sequential(log)


def test_chunks_tile_the_file_exactly(tmp_path: Path) -> None:
    """No gap (a lost line) and no overlap (a duplicated one)."""
    log = write(tmp_path / "access.log", 300)

    result = scan_chunks(log, parts=5)

    assert result.chunks[0].start == 0
    assert result.chunks[-1].end == log.stat().st_size
    for earlier, later in pairwise(result.chunks):
        assert earlier.end == later.start


def test_every_chunk_begins_on_a_line_boundary(tmp_path: Path) -> None:
    log = write(tmp_path / "access.log", 300)
    raw = log.read_bytes()

    result = scan_chunks(log, parts=6)

    for chunk in result.chunks:
        assert chunk.start == 0 or raw[chunk.start - 1 : chunk.start] == b"\n"


def test_the_digest_matches_the_streaming_reader(tmp_path: Path) -> None:
    """The scan reads the file anyway, so it computes the hash rather than
    making a second pass over gigabytes to get one."""
    log = write(tmp_path / "access.log", 200)

    result = scan_chunks(log, parts=4)

    assert result.sha256 == hashlib.sha256(log.read_bytes()).hexdigest()
    with open_log(log) as stream:
        list(stream)
        assert result.sha256 == stream.sha256


def test_more_parts_than_lines_does_not_produce_empty_or_overlapping_chunks(
    tmp_path: Path,
) -> None:
    """A tiny log asked to split sixteen ways. Every chunk must still hold work,
    or a worker is spawned to do nothing and the boundaries stop lining up."""
    log = write(tmp_path / "access.log", 3)

    result = scan_chunks(log, parts=16)

    assert all(chunk.end > chunk.start for chunk in result.chunks)
    assert chunked(log, result) == sequential(log)


def test_an_empty_file_yields_nothing_rather_than_failing(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text("", encoding="utf-8")

    result = scan_chunks(log, parts=4)

    assert chunked(log, result) == []
    assert result.total_lines == 0


def test_the_line_count_matches_what_the_reader_yields(tmp_path: Path) -> None:
    log = write(tmp_path / "access.log", 137, trailing_newline=False)

    assert scan_chunks(log, parts=4).total_lines == len(sequential(log))


def test_a_byte_order_mark_is_stripped_only_from_the_first_chunk(tmp_path: Path) -> None:
    """Left in place it becomes part of the first field, which splits one client
    into two everywhere downstream. Only line 1 can carry one."""
    log = tmp_path / "access.log"
    log.write_bytes("﻿line 1\nline 2\nline 3\nline 4\n".encode())

    result = scan_chunks(log, parts=2)

    assert chunked(log, result) == sequential(log)
    assert chunked(log, result)[0][1] == "line 1"


def test_a_range_reports_the_line_numbers_the_scan_promised(tmp_path: Path) -> None:
    """The chain of custody. A worker starting mid-file has no other way to know
    where it is, and a wrong `EvidenceRef` points an investigator at the wrong
    line while looking entirely plausible."""
    log = write(tmp_path / "access.log", 100)

    result = scan_chunks(log, parts=4)

    for chunk in result.chunks:
        first = next(iter(read_range(log, chunk)))
        assert first[0] == chunk.first_line


def test_a_chunk_read_on_its_own_needs_nothing_from_the_others(tmp_path: Path) -> None:
    """Workers run in separate processes; a chunk that only reads correctly in
    sequence would work in tests and fail in production."""
    log = write(tmp_path / "access.log", 200)
    result = scan_chunks(log, parts=4)
    expected = dict(sequential(log))

    for chunk in reversed(result.chunks):
        for line_no, text in read_range(log, chunk):
            assert expected[line_no] == text


def test_a_chunk_is_picklable(tmp_path: Path) -> None:
    """Windows spawns workers rather than forking, so everything handed to one
    crosses a pickle boundary. A `Chunk` that could not make the trip would fail
    only on Windows, and only outside the test suite."""
    import pickle

    chunk = Chunk(start=0, end=10, first_line=1)

    assert pickle.loads(pickle.dumps(chunk)) == chunk


def test_reading_a_range_leaves_nothing_open(tmp_path: Path) -> None:
    """A worker parses several ranges of several files and then goes home.

    Every reader it opened has to be shut before then. One left to the garbage
    collector is a handle held over a log the investigator may want to move, and
    on Windows an open handle is enough to refuse that - which is the machine
    this tool is used on.

    Asserted on `ResourceWarning`, which is the interpreter saying exactly this
    and is off by default, so it says it to nobody unless asked.
    """
    log = write(tmp_path / "access.log", 400)
    chunks = scan_chunks(log, parts=4).chunks

    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always", ResourceWarning)
        for chunk in chunks:
            assert list(read_range(log, chunk)), "premise: the range had lines in it"
        gc.collect()

    left = [str(w.message) for w in seen if issubclass(w.category, ResourceWarning)]
    assert not left, f"reading {len(chunks)} ranges left {len(left)} open: {left[:2]}"
