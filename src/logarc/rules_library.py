"""The detection-rule packs a reader keeps in their settings.

`<logarc_home>/rules/`, beside the saved-format library and moved by the same
`LOGARC_HOME` override. Each pack is one `<name>.yaml`, openable in any editor;
`switched-off.json` lists the built-in rules the reader switched off.

**Only the window reads this folder.** The engine never does, and neither does the
command line: `evaluate`, `score-crs` and the published scores must not move
because of somebody's personal pack (ADR-0013). The window reads it here and
hands the result to `Case.rule_engine` as a `RuleSet`.

A pack in the folder that does not load — edited by hand, or written by a later
version — is left out and named, never deleted or rewritten. The other packs and
every built-in rule still apply.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from logarc.detect.rules import load_pack_text
from logarc.detect.ruleset import PackText, RuleSet, build_rules, sort_out
from logarc.parsers.library import logarc_home

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.detect.ruleset import BuiltInPack

__all__ = [
    "SWITCHED_OFF",
    "Library",
    "RulesLibraryError",
    "SavedPack",
    "delete_pack",
    "file_name_for",
    "import_pack",
    "in_force",
    "name_problem",
    "rules_dir",
    "save_pack",
    "switch_rule",
    "switched_off",
]

SWITCHED_OFF: Final = "switched-off.json"
_NAME: Final = re.compile(r"[A-Za-z0-9_-]+")
_NOT_IN_A_NAME: Final = re.compile(r"[^A-Za-z0-9_-]")


class RulesLibraryError(ValueError):
    """The library could not do what was asked: a name, or a file it cannot use."""


@dataclass(frozen=True, slots=True)
class SavedPack:
    """One pack in the folder, as the rules tab lists it."""

    name: str
    text: str
    note: str = ""
    problem: str = ""
    """Why it was left out, in the loader's words. Empty when it applies."""


@dataclass(frozen=True, slots=True)
class Library:
    """What the folder holds, and what of it applies."""

    ruleset: RuleSet
    packs: tuple[SavedPack, ...]
    trouble: str = ""
    """About the folder rather than a pack: a damaged `switched-off.json`."""

    @property
    def refused(self) -> dict[str, str]:
        return {pack.name: pack.problem for pack in self.packs if pack.problem}


def rules_dir() -> Path:
    """The reader's rule packs. It need not exist; a first run has none."""
    return logarc_home() / "rules"


def in_force(*, built_in: Sequence[BuiltInPack] | None = None) -> Library:
    """Every pack in the folder, and the rules that apply: those that load together.

    In name order, so which of two clashing packs is left out does not depend on
    the order the disk lists them in.
    """
    trouble = ""
    try:
        off = switched_off()
    except RulesLibraryError as exc:
        off, trouble = frozenset(), f"{exc} Every built-in rule is on until it is fixed."
    found = _read_packs()
    ruleset, refused = sort_out(
        [PackText(name, text) for name, text, unread in found if not unread],
        off,
        built_in=built_in,
    )
    packs = tuple(
        SavedPack(
            name,
            text,
            note=_note_of(text),
            problem=unread or (str(refused[name]) if name in refused else ""),
        )
        for name, text, unread in found
    )
    return Library(ruleset, packs, trouble)


def name_problem(name: str, *, replacing: str | None = None) -> str:
    """What is wrong with `name` for a pack, or nothing.

    Unique ignoring case, because Windows keeps one file for `Shop.yaml` and
    `shop.yaml`: the second save would overwrite the first.
    """
    if not name:
        return "A pack needs a name."
    if not _NAME.fullmatch(name):
        return "A name can hold letters, digits, - and _ only."
    for existing in _names():
        if existing.casefold() == name.casefold() and existing != replacing:
            return f"You already have a pack called {existing}."
    return ""


def file_name_for(stem: str) -> str:
    """A pack name from a file's name: `My Rules` becomes `My-Rules`."""
    return _NOT_IN_A_NAME.sub("-", stem)


def save_pack(
    name: str,
    text: str,
    *,
    replacing: str | None = None,
    built_in: Sequence[BuiltInPack] | None = None,
) -> Path:
    """Write `text` as the pack `name`, after checking it applies with the others.

    `replacing` is the pack being edited, so it may keep its name, and a new
    name renames it. Nothing is written when the name is taken or the pack would
    not load beside the packs that apply now; the last saved version keeps
    applying.
    """
    if problem := name_problem(name, replacing=replacing):
        raise RulesLibraryError(problem)
    current = in_force(built_in=built_in)
    others = tuple(pack for pack in current.ruleset.packs if pack.name != replacing)
    build_rules(
        RuleSet((*others, PackText(name, text)), current.ruleset.switched_off), built_in=built_in
    )

    folder = rules_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.yaml"
    old = folder / f"{replacing}.yaml" if replacing is not None else None
    if old is not None and replacing != name and old.exists():
        # Renamed first and written after, rather than written and the old one
        # deleted: on Windows `Shop.yaml` and `shop.yaml` are one file, and
        # deleting the old name deleted the pack just written.
        old.rename(path)
    _write(path, text)
    return path


def delete_pack(name: str) -> None:
    (rules_dir() / f"{name}.yaml").unlink(missing_ok=True)


def import_pack(path: Path, *, built_in: Sequence[BuiltInPack] | None = None) -> str:
    """Copy a pack from anywhere into the library, under its file's name.

    Checked first; a pack that does not load, a name that is taken, or a name
    left empty is refused with the reason, and nothing is copied.
    """
    name = file_name_for(path.stem)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RulesLibraryError(f"{path.name} could not be read: {exc}") from exc
    load_pack_text(f"{name}.yaml", text)
    save_pack(name, text, built_in=built_in)
    return name


def switched_off() -> frozenset[str]:
    """The built-in rules the reader switched off, by id."""
    path = rules_dir() / SWITCHED_OFF
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return frozenset()
    except (OSError, ValueError) as exc:
        raise RulesLibraryError(f"{SWITCHED_OFF} could not be read: {exc}.") from exc
    if not isinstance(stored, list) or not all(isinstance(item, str) for item in stored):
        raise RulesLibraryError(f"{SWITCHED_OFF} is not a list of rule ids.")
    return frozenset(stored)


def switch_rule(rule_id: str, *, on: bool) -> None:
    """Switch one built-in rule on or off. Ids no rule has are kept as they were."""
    try:
        current = switched_off()
    except RulesLibraryError:
        current = frozenset()
    wanted = current - {rule_id} if on else current | {rule_id}
    folder = rules_dir()
    folder.mkdir(parents=True, exist_ok=True)
    _write(folder / SWITCHED_OFF, json.dumps(sorted(wanted), indent=2))


def _names() -> list[str]:
    folder = rules_dir()
    if not folder.is_dir():
        return []
    return sorted((path.stem for path in folder.glob("*.yaml")), key=str.casefold)


def _read_packs() -> list[tuple[str, str, str]]:
    """`(name, text, why it could not be read)` for every pack file, in name order.

    A file that cannot be read is listed and left out like any pack that does
    not load, with empty text; reading it as an empty pack instead would have it
    apply nothing without a word.
    """
    packs = []
    for name in _names():
        try:
            packs.append((name, (rules_dir() / f"{name}.yaml").read_text(encoding="utf-8"), ""))
        except (OSError, UnicodeDecodeError) as exc:
            packs.append((name, "", f"{name}.yaml could not be read: {exc}"))
    return packs


def _note_of(text: str) -> str:
    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError:
        return ""
    note = payload.get("note") if isinstance(payload, dict) else None
    return note if isinstance(note, str) else ""


def _write(path: Path, text: str) -> None:
    """Replace `path` whole or not at all: a pack half written does not load."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)
