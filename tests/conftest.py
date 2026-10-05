"""Puts `tests/` on the import path, and keeps the suite out of the user's home.

pytest inserts a conftest's own directory before importing it, and that is
what lets `tests/gui` and `tests/report` reach `colours.py` beside it. The
arithmetic itself moved to that module: reached as `conftest` it was one
sibling directory away from being shadowed, and then was.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from logarc.detect.crs import AUTO_ENV
from logarc.parsers.registry import register_saved_formats

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture(autouse=True)
def _private_logarc_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point `LOGARC_HOME` at a directory this test owns.

    The saved-format library is a real file in the user's config directory. A
    test that saved a format would otherwise write into it, and one that
    asserted on the library's contents would read whatever the user happened to
    have — passing or failing on the machine rather than on the code.

    Autouse and unconditional: opting in per test would mean the day someone
    forgets is the day the suite starts editing a real investigator's setup.

    Do not prove this fixture is armed by switching `autouse` off and watching
    tests fail. They fail, and on the way they write a format library into the
    real config directory — which is the exact harm the fixture exists to
    prevent, done deliberately. `test_the_suite_cannot_reach_the_real_library`
    asserts on the resolved path instead, which proves the same thing without
    touching anything outside the test's own directory.
    """
    monkeypatch.setenv("LOGARC_HOME", str(tmp_path / "logarc-home"))
    # Reconcile the registry with the empty library this test now has. Saved
    # formats are installed into a module-level registry that outlives any one
    # test, so without this a format installed by an earlier test is still
    # reachable by name here — and `is_built_in` would then call it one.
    register_saved_formats()
    yield


@pytest.fixture(autouse=True)
def _crs_only_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep CRS from running by itself after every ingest the suite does.

    It runs after every scan by default, in the window and on the command
    line. Here that would put a sidecar process behind each of the hundreds of
    ingests that test something else — slower, and a different case on a
    machine with the sidecar built from one without it.

    The tests about that run take the switch back off with `delenv`. Set rather
    than `setdefault`, so a developer's own `LOGARC_CRS=on` cannot leak in.
    """
    monkeypatch.setenv(AUTO_ENV, "off")
