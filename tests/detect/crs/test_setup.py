"""Setting CRS up in a source checkout, once, on purpose: `zodiarc-dev setup-crs`.

The packaged Windows application carries the sidecar and the ruleset. A source
checkout has neither, and until this existed its reader was given two commands
to type — one of which cloned CRS's newest rules rather than the revision every
figure in this project was measured against. Fetching on first use would have
been quieter and is not offered: the tool promises no network, so it reaches for
one only when asked.

The fakes here stand in for `git`, `go` and the final check; what is tested is
which of them is asked for what, and what is said when one is missing.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from zodiarc.detect.crs import setup
from zodiarc.detect.crs.setup import CRS_REVISION, SetupError, setup_crs


class Tools:
    """Records commands, and does what git and go would do to the tree."""

    def __init__(self, root: Path, *, head: str = CRS_REVISION) -> None:
        self.root = root
        self.head = head
        self.commands: list[list[str]] = []

    def run(self, command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[:2] == ["git", "clone"]:
            rules = Path(command[-1]) / "rules"
            rules.mkdir(parents=True)
            (rules / "REQUEST-901-INITIALIZATION.conf").write_text("", encoding="utf-8")
        if "rev-parse" in command:
            return subprocess.CompletedProcess(command, 0, self.head + "\n", "")
        if "checkout" in command:
            self.head = command[-1]
        if command[1:2] == ["build"]:
            (self.root / "crs" / command[command.index("-o") + 1]).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    def asked(self, *words: str) -> bool:
        return any(all(word in command for word in words) for command in self.commands)


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    (tmp_path / "crs").mkdir()
    (tmp_path / "crs" / "main.go").write_text("package main\n", encoding="utf-8")
    return tmp_path


def _setup(root: Path, tools: Tools, *, go: str | None = "go") -> list[str]:
    return setup_crs(
        root,
        run=tools.run,
        which=lambda name: go if name == "go" else name,
        verify=lambda: None,
    )


def test_a_bare_checkout_gets_the_pinned_ruleset_and_a_built_sidecar(checkout: Path) -> None:
    tools = Tools(checkout, head="")

    said = _setup(checkout, tools)

    assert tools.asked("git", "clone", "https://github.com/coreruleset/coreruleset.git")
    assert tools.asked("checkout", "--detach", CRS_REVISION), "the pinned revision, not the newest"
    assert tools.asked("build", "-o", setup.binary_name())
    assert any(CRS_REVISION[:8] in line for line in said)


def test_what_is_already_in_place_is_left_alone(checkout: Path) -> None:
    rules = checkout / "vendor" / "coreruleset" / "rules"
    rules.mkdir(parents=True)
    (rules / "REQUEST-901-INITIALIZATION.conf").write_text("", encoding="utf-8")
    (checkout / "crs" / setup.binary_name()).write_text("", encoding="utf-8")
    tools = Tools(checkout)

    _setup(checkout, tools)

    assert not tools.asked("clone")
    assert not tools.asked("checkout")
    assert not tools.asked("build")


def test_a_ruleset_at_another_revision_is_moved_to_the_pin(checkout: Path) -> None:
    rules = checkout / "vendor" / "coreruleset" / "rules"
    rules.mkdir(parents=True)
    (rules / "REQUEST-901-INITIALIZATION.conf").write_text("", encoding="utf-8")
    tools = Tools(checkout, head="0" * 40)

    _setup(checkout, tools)

    assert tools.asked("fetch")
    assert tools.asked("checkout", "--detach", CRS_REVISION)


def test_a_sidecar_older_than_its_source_is_rebuilt(checkout: Path) -> None:
    binary = checkout / "crs" / setup.binary_name()
    binary.write_text("", encoding="utf-8")
    source = checkout / "crs" / "main.go"
    stale = binary.stat().st_mtime - 60
    import os

    os.utime(binary, (stale, stale))
    rules = checkout / "vendor" / "coreruleset" / "rules"
    rules.mkdir(parents=True)
    (rules / "REQUEST-901-INITIALIZATION.conf").write_text("", encoding="utf-8")
    assert binary.stat().st_mtime < source.stat().st_mtime
    tools = Tools(checkout)

    _setup(checkout, tools)

    assert tools.asked("build")


def test_without_go_it_says_what_to_install_and_what_needs_nothing(checkout: Path) -> None:
    tools = Tools(checkout, head="")

    with pytest.raises(SetupError) as raised:
        _setup(checkout, tools, go=None)

    message = str(raised.value)
    assert "go.dev" in message
    assert "packaged" in message


def test_a_directory_in_the_way_is_not_overwritten(checkout: Path) -> None:
    """Something at `vendor/coreruleset` that is not a CRS checkout is the
    reader's, and cloning over it would destroy it."""
    occupied = checkout / "vendor" / "coreruleset"
    occupied.mkdir(parents=True)
    (occupied / "notes.txt").write_text("mine", encoding="utf-8")
    tools = Tools(checkout, head="")

    with pytest.raises(SetupError, match="not a CRS checkout"):
        _setup(checkout, tools)

    assert (occupied / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert not tools.asked("clone")


def test_it_is_not_finished_until_crs_has_caught_something(checkout: Path) -> None:
    """Built and fetched is not the same as working. The last step replays a
    known payload, and a setup that cannot catch it says so."""
    tools = Tools(checkout, head="")

    def nothing_caught() -> None:
        raise SetupError("CRS ran but did not catch the test payload")

    with pytest.raises(SetupError, match="did not catch"):
        setup_crs(checkout, run=tools.run, which=lambda name: name, verify=nothing_caught)


def test_the_packaged_application_has_nothing_to_set_up(
    checkout: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.frozen", True, raising=False)
    tools = Tools(checkout, head="")

    said = _setup(checkout, tools)

    assert tools.commands == []
    assert any("already carries" in line for line in said)
