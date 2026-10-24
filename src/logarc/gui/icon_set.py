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
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Final

from logarc.core.activity import ActivityCategory
from logarc.detect.rules import RulePackError, load_pack_text
from logarc.gui.rule_form_view import CATEGORY_LABELS
from logarc.parsers.library import logarc_home

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from logarc.core.graph import GraphNode
    from logarc.detect.rules import Rule
    from logarc.detect.ruleset import RuleSet

__all__ = [
    "DEFAULT_ICONS",
    "FILE_PREFIX",
    "KIND_NAMES",
    "LUCIDE_VERSION",
    "Icon",
    "IconChoice",
    "file_name_of",
    "icons_dir",
    "is_known",
    "lucide",
    "rule_icons",
    "search",
    "unknown_icon_note",
    "unknown_icons",
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


@dataclass(frozen=True, slots=True)
class IconChoice:
    """What the reader chose: icons for kinds, and the icons their own rules name."""

    kinds: Mapping[ActivityCategory, str] = field(default_factory=dict)
    rules: Mapping[str, str] = field(default_factory=dict)
    """By rule id. Only the reader's rules can name one."""

    def candidates(self, node: GraphNode) -> tuple[str, ...]:
        """The icons `node` could carry, best first; whoever draws takes the first that draws.

        The icon of the rule the activity is named after, then the reader's
        icon for its kind, then the kind's own. Only the naming rule counts: a
        rule that merely matched inside the activity did not make it what it is.
        """
        found = (
            self.rules.get(node.named_by),
            self.kinds.get(node.category),
            DEFAULT_ICONS[node.category],
        )
        return tuple(dict.fromkeys(value for value in found if value))


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


def rule_icons(ruleset: RuleSet) -> dict[str, str]:
    """Each of the reader's rules that names an icon, by id.

    Read from the packs' text, so it needs no engine. A pack that does not load
    contributes nothing: its rules are not in force either.
    """
    icons: dict[str, str] = {}
    for pack in ruleset.packs:
        try:
            rules = load_pack_text(f"{pack.name}.yaml", pack.text)
        except RulePackError:
            continue
        icons.update({rule.id: rule.icon for rule in rules if rule.icon})
    return icons


def unknown_icons(rules: Sequence[Rule]) -> list[str]:
    """The icons `rules` name that nothing answers to, each once, in rule order."""
    seen: dict[str, None] = {}
    for rule in rules:
        if rule.icon and not is_known(rule.icon):
            seen.setdefault(rule.icon)
    return list(seen)


def unknown_icon_note(values: Sequence[str]) -> str:
    """One sentence saying which icons are unknown and what is drawn instead."""
    if not values:
        return ""
    if len(values) == 1:
        return f"Icon {values[0]} is not one logarc knows, so its kind's icon is drawn."
    listed = ", ".join(values[:-1]) + f" and {values[-1]}"
    return f"Icons {listed} are not ones logarc knows, so their kinds' icons are drawn."
