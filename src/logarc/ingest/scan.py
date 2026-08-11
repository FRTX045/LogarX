"""Splitting a log into byte ranges that can be parsed independently.

Parallel ingest needs three things a worker cannot work out for itself, and one
sequential pass over the file produces all three:

* **Where to cut.** Ranges must begin on a line boundary, or the first and last
  lines of every chunk are torn in half.
* **What line each range starts at.** `EvidenceRef` carries a line number and it
  is the chain of custody — the point of the whole tool. A worker opening the
  file at byte 25,000,000 has no idea it is at line 130,457, and counting from
  the start itself would undo the parallelism it exists to enable.
* **The digest.** SHA-256 covers the file as stored and has to be computed in
  order, so it cannot be assembled from ranges read out of sequence.

The pass is a raw byte scan — no decoding, no parsing — and runs at disk speed:
around a second per gigabyte against the several minutes the parse costs. Paying
it to make the expensive half parallel is the trade this module exists for.

Compressed logs are not splittable: gzip and bzip2 have no random access, so
there is no way to begin reading at an arbitrary offset. Callers fall back to a
sequential ingest for those rather than pretending otherwise.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = ["Chunk", "ScanResult", "read_range", "scan_chunks"]

#: Bytes read per step of the scan. Large enough that the syscall cost vanishes,
#: small enough not to matter against the ingest that follows.
_BLOCK: Final = 4 << 20

_BOM: Final = "﻿"


@dataclass(frozen=True, slots=True)
class Chunk:
    """One worker's share of a log: a byte range, and where it starts.

    Frozen and made of three integers so it survives the pickling that spawning
    a worker on Windows requires.
    """

    start: int
    """Byte offset of the first line, always at a line start."""

    end: int
    """Byte offset just past the chunk's last newline; exclusive."""

    first_line: int
    """1-based number of the line at `start`, as the sequential reader counts."""


@dataclass(frozen=True, slots=True)
class ScanResult:
    """What one pass over the file established."""

    sha256: str
    size_bytes: int
    total_lines: int
    chunks: tuple[Chunk, ...]


def scan_chunks(path: Path, *, parts: int, block_size: int = _BLOCK) -> ScanResult:
    """Read `path` once, and return how to divide it into `parts` ranges.

    Fewer ranges than asked for is normal and correct: a cut is moved forward to
    the next line boundary, so on a file with fewer lines than `parts` several
    cuts land in the same place and collapse. Returning an empty range instead
    would spawn a worker to do nothing.
    """
    path = Path(path)
    size = path.stat().st_size
    digest = hashlib.sha256()

    if size == 0:
        return ScanResult(digest.hexdigest(), 0, 0, ())

    parts = max(1, parts)
    # Cuts are wanted at even fractions of the file; each is then moved forward
    # to the end of whatever line it landed inside.
    wanted = [(index * size) // parts for index in range(1, parts)]

    starts: list[tuple[int, int]] = [(0, 1)]  # (byte offset, line number)
    pending = 0
    offset = 0
    newlines = 0
    last_byte = b""

    with path.open("rb") as handle:
        while block := handle.read(block_size):
            digest.update(block)

            while pending < len(wanted) and wanted[pending] < offset + len(block):
                # A cut that landed in an earlier block resolves from this one's
                # beginning, which is what clamping at zero expresses.
                from_here = max(wanted[pending] - offset, 0)
                position = block.find(b"\n", from_here)
                if position == -1:
                    break  # the line runs into a later block; resolve it there
                start = offset + position + 1
                if start < size and start > starts[-1][0]:
                    # +1 for the newline just passed, +1 to name the next line.
                    starts.append((start, newlines + block.count(b"\n", 0, position + 1) + 1))
                pending += 1

            newlines += block.count(b"\n")
            last_byte = block[-1:]
            offset += len(block)

    # A file not ending in a newline still holds a final line. Logs get
    # truncated mid-write, and dropping that line would lose evidence quietly.
    total_lines = newlines + (1 if last_byte != b"\n" else 0)

    bounds = [start for start, _ in starts] + [size]
    chunks = tuple(
        Chunk(start=start, end=bounds[index + 1], first_line=first_line)
        for index, (start, first_line) in enumerate(starts)
    )
    return ScanResult(digest.hexdigest(), size, total_lines, chunks)


def read_range(path: Path, chunk: Chunk) -> Iterator[tuple[int, str]]:
    """Yield `(line_number, text)` for one chunk, exactly as `LogStream` would.

    Self-contained by design: a worker in another process holds nothing but the
    path and the chunk, so anything this needed from its neighbours would be a
    bug that only appears once the work is really distributed.
    """
    if chunk.end <= chunk.start:
        return

    remaining = chunk.end - chunk.start
    line_no = chunk.first_line

    with Path(path).open("rb") as handle:
        handle.seek(chunk.start)
        consumed = 0
        for raw in io.BufferedReader(handle):
            consumed += len(raw)
            text = raw.decode("utf-8", errors="surrogateescape").rstrip("\r\n")
            # Only the true first line of the file can carry a mark; anywhere
            # else the same bytes are content.
            if line_no == 1 and text.startswith(_BOM):
                text = text[1:]
            yield line_no, text
            line_no += 1
            if consumed >= remaining:
                return
