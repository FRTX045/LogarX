"""Shared set-up for the command-line tests."""

from __future__ import annotations

import pytest

from logarc.cli import support


@pytest.fixture(autouse=True)
def _console_width_follows_each_invocation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let a test's `env={"COLUMNS": ...}` set the width it asks for.

    Rich reads `COLUMNS` once, when a console is built, and keeps it — so the
    width of these module-level consoles is whatever the test process happened
    to have when `logarc.cli` was first imported, and a later `invoke(env=...)`
    cannot change it. Serially that is nothing, and the width is read again on
    every print. Under pytest-xdist on Linux it is 80: something in the
    controller imports `readline`, GNU readline exports `COLUMNS=80` into the
    C environment when there is no terminal, and every worker inherits it.

    So the activity table wrapped a rule name across lines and an assertion
    about that name failed on Linux workers only. Clearing the stored width
    puts each test back on the one it passed, whatever ran the suite.
    """
    for console in (support.console, support.errors):
        monkeypatch.setattr(console, "_width", None)
