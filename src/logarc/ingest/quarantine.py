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

    def __init__(self, case_root: Path) -> None:
        self.path = Path(case_root) / DIRECTORY_NAME / FILE_NAME
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

    def __enter__(self) -> Quarantine:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
