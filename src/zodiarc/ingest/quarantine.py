"""Records log lines that could not be parsed.

Silently discarding a line an investigator would have wanted to see is the
worst failure mode this tool has: the result looks complete and is not. Every
line that does not become an event is written out with its origin and the
reason, so a low event count can always be explained.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import TracebackType
from typing import IO, Final

__all__ = ["Quarantine"]

DIRECTORY_NAME: Final = "quarantine"
FILE_NAME: Final = "unparsed.jsonl"


class Quarantine:
    """Append-only record of unparseable lines within a case.

    The file is created lazily, so a clean ingest leaves no empty artefact
    behind to be mistaken for a problem.
    """

    def __init__(self, case_root: Path, *, shard: str | None = None) -> None:
        """`shard` gives this quarantine a file of its own within the case.

        Parallel ingest runs one per worker. They could all append to a single
        file — but an append from several processes is not guaranteed atomic on
        Windows, and a torn write would corrupt the record of precisely the
        lines that were already too damaged to parse. Each writes its own part
        and `merge` joins them when the ingest is done.
        """
        directory = Path(case_root) / DIRECTORY_NAME
        name = FILE_NAME if shard is None else f"unparsed-{shard}.jsonl"
        self.path = directory / name
        self._handle: IO[str] | None = None
        self.count = 0

    def record(self, source_file_id: str, line_no: int, line: str, *, reason: str) -> None:
        entry = {
            "source_file_id": source_file_id,
            "line_no": line_no,
            "reason": reason,
            "line": line,
        }
        # Lines land here precisely because they are malformed, so serialising
        # them must not be what fails. Undecodable bytes become escapes.
        text = json.dumps(entry, ensure_ascii=False)
        self._open().write(text.encode("utf-8", "backslashreplace").decode("utf-8") + "\n")
        self.count += 1

    def _open(self) -> IO[str]:
        if self._handle is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("a", encoding="utf-8")
        return self._handle

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    @staticmethod
    def merge(case_root: Path) -> int:
        """Join the per-worker parts into the one file a case is read from.

        Returns how many lines were quarantined in total. The parts are removed
        once joined: leaving them beside the merged file would record the same
        lines twice, and every count taken from the directory would double.
        """
        directory = Path(case_root) / DIRECTORY_NAME
        parts = sorted(directory.glob("unparsed-*.jsonl")) if directory.exists() else []
        if not parts:
            return 0

        total = 0
        with (directory / FILE_NAME).open("a", encoding="utf-8") as merged:
            for part in parts:
                with part.open(encoding="utf-8") as handle:
                    for line in handle:
                        if line.strip():
                            merged.write(line)
                            total += 1
                part.unlink()
        return total

    def __enter__(self) -> Quarantine:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
