"""Tests for the streaming log reader."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
from pathlib import Path

import pytest

from zodiarc.ingest.reader import Compression, LogSourceError, open_log

SAMPLE = "line one\nline two\nline three\n"


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_plain_file_yields_lines_numbered_from_one(tmp_path: Path) -> None:
    path = write(tmp_path / "access.log", SAMPLE.encode())

    with open_log(path) as stream:
        assert list(stream) == [(1, "line one"), (2, "line two"), (3, "line three")]


def test_trailing_newline_is_stripped_but_content_is_not(tmp_path: Path) -> None:
    path = write(tmp_path / "access.log", b"  padded  \r\n")

    with open_log(path) as stream:
        assert list(stream) == [(1, "  padded  ")]


def test_final_line_without_a_newline_is_still_read(tmp_path: Path) -> None:
    path = write(tmp_path / "access.log", b"a\nb")

    with open_log(path) as stream:
        assert list(stream) == [(1, "a"), (2, "b")]


def test_empty_file_yields_no_lines(tmp_path: Path) -> None:
    path = write(tmp_path / "access.log", b"")

    with open_log(path) as stream:
        assert list(stream) == []


@pytest.mark.parametrize(
    ("compress", "expected"),
    [
        (gzip.compress, Compression.GZIP),
        (bz2.compress, Compression.BZIP2),
        (lzma.compress, Compression.XZ),
    ],
)
def test_compressed_logs_are_read_transparently(
    tmp_path: Path,
    compress: object,
    expected: Compression,
) -> None:
    path = write(tmp_path / "access.log.archive", compress(SAMPLE.encode()))  # type: ignore[operator]

    with open_log(path) as stream:
        assert stream.compression is expected
        assert [line for _, line in stream] == ["line one", "line two", "line three"]


def test_compression_is_detected_from_content_not_the_file_name(tmp_path: Path) -> None:
    """Evidence arrives with whatever name it was seized under. A gzipped file
    called `.log` must still be read, not quarantined as garbage."""
    path = write(tmp_path / "access.log", gzip.compress(SAMPLE.encode()))

    with open_log(path) as stream:
        assert stream.compression is Compression.GZIP
        assert len(list(stream)) == 3


def test_byte_order_mark_is_not_left_in_the_first_field(tmp_path: Path) -> None:
    """Windows tools write UTF-8 with a BOM. Left in place it becomes part of
    the first field, silently splitting one client into two in the results."""
    path = write(tmp_path / "access.log", b"\xef\xbb\xbf1.2.3.4 first\n5.6.7.8 second\n")

    with open_log(path) as stream:
        assert list(stream) == [(1, "1.2.3.4 first"), (2, "5.6.7.8 second")]


def test_byte_order_mark_is_still_covered_by_the_integrity_hash(tmp_path: Path) -> None:
    """The BOM is part of the file as seized, even though it is not data."""
    payload = b"\xef\xbb\xbfline\n"
    path = write(tmp_path / "access.log", payload)

    with open_log(path) as stream:
        list(stream)
        digest = stream.sha256

    assert digest == hashlib.sha256(payload).hexdigest()


def test_a_mark_appearing_later_in_the_file_is_left_alone(tmp_path: Path) -> None:
    """Only a leading mark is an encoding artefact; elsewhere it is content."""
    path = write(tmp_path / "access.log", "first\n﻿second\n".encode())

    with open_log(path) as stream:
        assert list(stream) == [(1, "first"), (2, "﻿second")]


def test_invalid_utf8_bytes_survive_the_round_trip(tmp_path: Path) -> None:
    """Attack payloads contain arbitrary bytes. Decoding must never fail and
    must never silently replace them, or the evidence is altered."""
    raw = b"GET /caf\xe9\xff\xfe HTTP/1.1\n"
    path = write(tmp_path / "access.log", raw)

    with open_log(path) as stream:
        lines = list(stream)

    assert len(lines) == 1
    assert lines[0][1].encode("utf-8", errors="surrogateescape") == raw.rstrip(b"\n")


def test_sha256_matches_the_file_on_disk(tmp_path: Path) -> None:
    payload = SAMPLE.encode()
    path = write(tmp_path / "access.log", payload)

    with open_log(path) as stream:
        list(stream)
        digest = stream.sha256

    assert digest == hashlib.sha256(payload).hexdigest()


def test_sha256_covers_the_compressed_bytes_that_are_the_actual_evidence(
    tmp_path: Path,
) -> None:
    payload = gzip.compress(SAMPLE.encode())
    path = write(tmp_path / "access.log.gz", payload)

    with open_log(path) as stream:
        list(stream)
        digest = stream.sha256

    assert digest == hashlib.sha256(payload).hexdigest()


def test_reading_the_hash_before_the_stream_is_consumed_is_an_error(tmp_path: Path) -> None:
    """A partial hash is worse than none: it looks like an integrity record but
    does not identify the file."""
    path = write(tmp_path / "access.log", SAMPLE.encode())

    with open_log(path) as stream, pytest.raises(LogSourceError, match="fully read"):
        _ = stream.sha256


def test_bytes_read_tracks_progress_through_the_file(tmp_path: Path) -> None:
    payload = SAMPLE.encode()
    path = write(tmp_path / "access.log", payload)

    with open_log(path) as stream:
        list(stream)
        assert stream.bytes_read == len(payload)


def test_missing_file_reports_the_path(tmp_path: Path) -> None:
    with pytest.raises(LogSourceError, match=r"nope\.log"), open_log(tmp_path / "nope.log"):
        pass


def test_directory_instead_of_a_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(LogSourceError), open_log(tmp_path):
        pass


def test_size_bytes_reports_the_on_disk_size(tmp_path: Path) -> None:
    payload = SAMPLE.encode()
    path = write(tmp_path / "access.log", payload)

    with open_log(path) as stream:
        assert stream.size_bytes == len(payload)
