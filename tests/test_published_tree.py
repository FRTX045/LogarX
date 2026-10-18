"""What the published tree may and may not point a reader at."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: The project's working list. It is kept out of the repository, so a published
#: file that sends a reader there sends them to a file they do not have.
UNPUBLISHED = "TODO" + ".md"


def _published() -> list[Path]:
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout, so there is no published tree to read")
    listed = subprocess.run(
        [git, "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.split(b"\0")
    return [ROOT / name.decode("utf-8") for name in listed if name]


def test_no_published_file_points_at_the_unpublished_todo_list() -> None:
    """Six did, found on 2026-10-17: the rule-pack ledger four times, a CRS
    mapping comment and a rule pack's comment. Each sent the reader to the
    working list by name, and the reader has no such file.

    This file names it only in pieces, so as not to be one of them. Checked
    with it committed: run before then, `git ls-files` does not list the test
    and it cannot see itself, which is how a first version passed here and
    failed on CI."""
    pointing = [
        str(path.relative_to(ROOT))
        for path in _published()
        if path.is_file() and UNPUBLISHED.encode() in path.read_bytes()
    ]

    assert pointing == []
