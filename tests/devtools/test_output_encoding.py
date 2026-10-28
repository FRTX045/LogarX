"""Output sent to a file, a pipe or `NUL` survives any character a log holds.

Found 2026-10-05. On Windows, Python encodes redirected output in the locale's
code page — cp1252 here — and refuses anything outside it. A log line is
whatever the client sent, so evidence redirected to a file stopped half way
with a traceback on a User-Agent in Chinese, and every command showing Rich's
progress spinner failed outright on `> NUL`, which Windows reports as a
terminal: the spinner's braille is not in cp1252 either. The second surfaced as
`error: 'charmap' codec …` and exit 1, because `UnicodeEncodeError` is a
`ValueError` and the commands report those as the user's mistake.

These run the command line in its own process with its output on a real file,
because that is the only way to get the stream Python would really choose.
`CliRunner` hands commands a UTF-8 stream of its own and would pass either way.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

LINE = (
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /search?q=%E4%B8%AD%E6%96%87 HTTP/1.1" '
    '200 2326 "-" "Mozilla/5.0 (中文浏览器)"'
)


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text(LINE + "\n", encoding="utf-8")
    return path


def _ingest(log: Path, tmp_path: Path, **env: str) -> tuple[int, bytes]:
    """`logarx-dev ingest` in its own process, stdout on a file, into a case
    whose path is written in Chinese, which the command prints back. Returns
    the exit code and the bytes written."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONIOENCODING", "PYTHONUTF8"}
    }
    environment.update(env)
    out = tmp_path / "out.txt"
    with out.open("wb") as handle:
        done = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from logarx.devtools.main import app; "
                "sys.argv[0] = 'logarx-dev'; app()",
                "ingest",
                str(log),
                "--case",
                str(tmp_path / "中文案例"),
                "--no-crs",
            ],
            stdout=handle,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
    assert b"Traceback" not in done.stderr, done.stderr.decode("utf-8", "replace")
    return done.returncode, out.read_bytes()


def test_output_redirected_to_a_file_keeps_every_character(log: Path, tmp_path: Path) -> None:
    """Python's own default for a redirect, UTF-8 mode off. On Windows that is
    the code page, which is where it broke; elsewhere it is UTF-8 already, and
    this holds either way. UTF-8 because it loses nothing."""
    code, written = _ingest(log, tmp_path, PYTHONUTF8="0")

    assert code == 0
    assert "中文案例" in written.decode("utf-8")


def test_a_chosen_encoding_is_kept_and_nothing_crashes(log: Path, tmp_path: Path) -> None:
    """Somebody who set `PYTHONIOENCODING` chose it, so it is kept. What it
    cannot hold is written as an escape rather than failing the command — and
    this is the case that reproduces the crash on every platform, not only on
    Windows."""
    code, written = _ingest(log, tmp_path, PYTHONIOENCODING="cp1252")

    assert code == 0
    assert "\\u4e2d\\u6587" in written.decode("cp1252")
