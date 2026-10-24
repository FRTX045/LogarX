"""The icons an activity can carry, and which one each kind starts with.

Lucide 0.452.0, shipped whole in `lucide.json` and written by
`tools/lucide_data.py`. Whole because the reader picks: the fourteen kinds need
fourteen, and a reader giving one of their own rules an icon may want a shop
trolley nobody here thought of.

No Qt in this module. Whether a name means anything, which icon a kind starts
with and what the kinds are called are facts about data; drawing them is
`icons.py`'s job.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Final

from logarc.core.activity import ActivityCategory
from logarc.gui.rule_form_view import CATEGORY_LABELS
from logarc.parsers.library import logarc_home

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "DEFAULT_ICONS",
    "FILE_PREFIX",
    "KIND_NAMES",
    "LUCIDE_VERSION",
    "Icon",
    "file_name_of",
    "icons_dir",
    "is_known",
    "lucide",
    "search",
]

LUCIDE_VERSION: Final = "0.452.0"

_DATA: Final = Path(__file__).with_name("lucide.json")

#: The icon each kind starts with, until the reader picks another.
DEFAULT_ICONS: Final[Mapping[ActivityCategory, str]] = {
    ActivityCategory.BROWSING: "globe",
    ActivityCategory.STATIC_ASSET: "image",
    ActivityCategory.API_CALL: "braces",
    ActivityCategory.AUTHENTICATION: "log-in",
    ActivityCategory.CRAWLING: "bot",
    ActivityCategory.RECONNAISSANCE: "radar",
    ActivityCategory.ENUMERATION: "folder-search",
    ActivityCategory.INJECTION: "syringe",
    ActivityCategory.PATH_TRAVERSAL: "folder-up",
    ActivityCategory.ACCESS_CONTROL: "lock-open",
    ActivityCategory.CREDENTIAL_ATTACK: "key-round",
    ActivityCategory.SSRF: "server",
    ActivityCategory.EXPLOITATION: "zap",
    ActivityCategory.UNKNOWN: "circle-help",
}

#: What each kind is called wherever icons are listed. Add rule's names, and
#: `Unknown`, which no rule can be but an activity can.
KIND_NAMES: Final[Mapping[ActivityCategory, str]] = {
    kind: CATEGORY_LABELS.get(kind, "Unknown") for kind in ActivityCategory
}

#: An icon of the reader's own, by its name in `icons_dir()`.
FILE_PREFIX: Final = "file:"


@dataclass(frozen=True, slots=True)
class Icon:
    name: str
    svg: str
    tags: tuple[str, ...]


@cache
def lucide() -> Mapping[str, Icon]:
    """Every shipped icon by name, read once."""
    data = json.loads(_DATA.read_text(encoding="utf-8"))
    return {
        name: Icon(name, entry["svg"], tuple(entry["tags"]))
        for name, entry in data["icons"].items()
    }


def search(text: str) -> list[str]:
    """The icons whose name or tags hold every word of `text`.

    Names that start with the text first, then names holding it, then those
    found only by a tag, each alphabetically: a reader typing `lock` wants the
    lock before the key that unlocks.
    """
    wanted = text.casefold().split()
    if not wanted:
        return sorted(lucide())
    phrase = " ".join(wanted)
    found: tuple[list[str], list[str], list[str]] = ([], [], [])
    for name, icon in lucide().items():
        words = (name, *(tag.casefold() for tag in icon.tags))
        if not all(any(word in said for said in words) for word in wanted):
            continue
        if name.startswith(phrase):
            found[0].append(name)
        elif all(word in name for word in wanted):
            found[1].append(name)
        else:
            found[2].append(name)
    return [name for group in found for name in sorted(group)]


def file_name_of(value: str) -> str | None:
    """The file a `file:` value names, or None when it is not a bare file name.

    Bare, so a pack shared by someone else cannot point the window at a file
    anywhere on the reader's disk: the name is looked up in `icons_dir()` and
    nowhere else.
    """
    if not value.startswith(FILE_PREFIX):
        return None
    name = value[len(FILE_PREFIX) :]
    if not name or "/" in name or "\\" in name or ".." in name:
        return None
    return name


def icons_dir() -> Path:
    """Where the reader's own icons are kept: beside their rules."""
    return logarc_home() / "icons"


def is_known(value: str) -> bool:
    """Whether `value` names an icon that is there: shipped, or a file of the reader's."""
    if value in lucide():
        return True
    name = file_name_of(value)
    return name is not None and (icons_dir() / name).is_file()
