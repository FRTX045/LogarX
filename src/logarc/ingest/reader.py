"""Streaming access to a log file, whatever shape it arrives in.

Three concerns are handled here so that nothing downstream has to:

* **Compression** is detected from the file's leading bytes rather than its
  name. Evidence arrives named however it was seized, and a gzipped file called
  `access.log` must still be readable.
* **Decoding never fails.** Logs contain arbitrary bytes — that is the whole
  point when the payload is an attack. Bytes that are not valid UTF-8 are
  preserved via surrogate escapes rather than replaced, so the original stays
  recoverable.
* **Integrity** is recorded in the same pass. The SHA-256 covers the bytes on
  disk, which is the artefact an investigator actually holds.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import IO, TYPE_CHECKING, BinaryIO, Final, cast

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = ["Compression", "LogSourceError", "LogStream", "open_log"]


class LogSourceError(OSError):
    """Raised when a log file cannot be opened or read."""


class Compression(Enum):
    """How a log file is compressed, detected from its leading bytes."""

    NONE = "none"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"


_MAGIC: Final[tuple[tuple[bytes, Compression], ...]] = (
    (b"\x1f\x8b", Compression.GZIP),
    (b"BZh", Compression.BZIP2),
    (b"\xfd7zXZ\x00", Compression.XZ),
)

#: Longest magic number we look for, and therefore how much we must peek.
_PEEK = max(len(magic) for magic, _ in _MAGIC)


def _detect(header: bytes) -> Compression:
    for magic, compression in _MAGIC:
        if header.startswith(magic):
            return compression
    return Compression.NONE


def _decompressed(compression: Compression, raw: IO[bytes]) -> IO[bytes]:
    """Wrap `raw` in the matching decompressor, or return it unchanged.

    The casts are unavoidable: the standard library's compressed file objects
    implement the binary IO interface without declaring it.
    """
    if compression is Compression.GZIP:
        return cast("IO[bytes]", gzip.GzipFile(fileobj=raw))
    if compression is Compression.BZIP2:
        return cast("IO[bytes]", bz2.BZ2File(raw))
    if compression is Compression.XZ:
        return cast("IO[bytes]", lzma.LZMAFile(raw))
    return raw


class _HashingReader(io.RawIOBase):
    """Passes bytes through untouched while accumulating their digest.

    Sitting below decompression means the digest covers the file as stored,
    letting integrity be recorded in the same pass that reads it — no second
    walk over a multi-gigabyte file.

    Implemented as a raw stream so `io.BufferedReader` can wrap it and supply
    buffered line iteration, which is both faster and less code than doing our
    own line splitting.
    """

    def __init__(self, raw: BinaryIO) -> None:
        super().__init__()
        self._raw = raw
        self._digest = hashlib.sha256()
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        chunk = self._raw.read(len(buffer))
        count = len(chunk)
        buffer[:count] = chunk
        self._digest.update(chunk)
        self.bytes_read += count
        return count

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


class LogStream:
    """An open log file, iterable as `(line_number, text)` pairs.

    Line numbers are 1-based to match what an investigator sees in an editor.
    """

    def __init__(self, source: Path, compression: Compression, size_bytes: int) -> None:
        self.path = source
        self.compression = compression
        self.size_bytes = size_bytes
        self._hasher: _HashingReader | None = None
        self._stream: IO[bytes] | None = None
        self._exhausted = False

    def __iter__(self) -> Iterator[tuple[int, str]]:
        if self._stream is None:  # pragma: no cover - guarded by open_log
            raise LogSourceError(f"{self.path} is not open")
        for number, raw in enumerate(self._stream, start=1):
            text = raw.decode("utf-8", errors="surrogateescape").rstrip("\r\n")
            # A leading byte order mark is an encoding artefact, not data. Left
            # in place it becomes part of the first field, which quietly splits
            # one client into two everywhere downstream. Only the very first
            # line can carry one; a mark anywhere else is content.
            if number == 1 and text.startswith("﻿"):
                text = text[1:]
            yield number, text
        self._exhausted = True

    @property
    def bytes_read(self) -> int:
        """Compressed bytes consumed so far. Drives progress reporting."""
        return self._hasher.bytes_read if self._hasher else 0

    @property
    def sha256(self) -> str:
        """Digest of the file as stored on disk.

        Only available once the stream has been read to the end: a digest over
        part of a file looks like an integrity record but identifies nothing.
        """
        if not self._exhausted or self._hasher is None:
            raise LogSourceError(f"{self.path} has not been fully read; digest is incomplete")
        return self._hasher.hexdigest()


@contextmanager
def open_log(path: Path) -> Iterator[LogStream]:
    """Open a log file for streaming, decompressing it if necessary."""
    path = Path(path)
    try:
        size = path.stat().st_size
        handle = path.open("rb")
    except OSError as exc:
        raise LogSourceError(f"cannot open log file {path}: {exc}") from exc

    with handle:
        compression = _detect(handle.read(_PEEK))
        handle.seek(0)

        hasher = _HashingReader(handle)
        byte_stream = _decompressed(compression, io.BufferedReader(hasher))

        stream = LogStream(path, compression, size)
        stream._hasher = hasher
        stream._stream = byte_stream
        try:
            yield stream
        finally:
            byte_stream.close()
