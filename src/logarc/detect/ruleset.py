"""Which rules are in force: the built-in packs, less any a reader switched off, plus theirs.

Data rather than paths. The window reads a reader's packs from their settings
(`rules_library`) and hands them over as text, so the scan worker it spawns
labels with exactly what the window holds — not with whatever a file says by the
time the child reads it. The same move ADR-0010 made for formats.

Every front end builds its rules here, through `Case.rule_engine`, and that is
what keeps the window, *Where to start* and a report agreeing about which rules a
finding came from. The command line passes files (`extra_packs`); only the window
passes a `RuleSet`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.detect.rulepacks import DEFAULT_RULEPACK_DIR
from logarc.detect.rules import RulePackError, load_pack_text, load_rules
from logarc.style import plural

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from logarc.detect.rules import Rule

__all__ = [
    "NO_EXTRA_RULES",
    "BuiltInPack",
    "InForce",
    "PackText",
    "RuleSet",
    "build_rules",
    "built_in_packs",
    "sort_out",
]


@dataclass(frozen=True, slots=True)
class PackText:
    """One of a reader's packs: its name, without `.yaml`, and its YAML."""

    name: str
    text: str


@dataclass(frozen=True, slots=True)
class RuleSet:
    """What a reader added to the built-in rules, and which of those they switched off."""

    packs: tuple[PackText, ...] = ()
    switched_off: frozenset[str] = frozenset()


NO_EXTRA_RULES: Final = RuleSet()


@dataclass(frozen=True, slots=True)
class BuiltInPack:
    """A pack shipped with logarc, named as the rules tab lists it."""

    name: str
    path: Path
    rules: tuple[Rule, ...]


#: Named by file, the way formats are — except the one file whose name says
#: nothing on its own.
_NAMED: Final = {"action/global.yaml": "actions"}


def built_in_packs() -> tuple[BuiltInPack, ...]:
    """Every pack shipped with logarc, in the order the rules tab lists them.

    Loads them all, which takes about 170 ms. A caller checking a pack over and
    over — the rules tab, as the reader types — loads them once and passes them
    to `build_rules` as `built_in`.
    """
    packs = []
    for path in sorted(DEFAULT_RULEPACK_DIR.rglob("*.yaml")):
        relative = path.relative_to(DEFAULT_RULEPACK_DIR).as_posix()
        packs.append(BuiltInPack(_NAMED.get(relative, path.stem), path, tuple(load_rules([path]))))
    return tuple(packs)


@dataclass(frozen=True, slots=True)
class InForce:
    """The rules an engine is built from, and what a report says about them."""

    rules: tuple[Rule, ...]
    described: str


def build_rules(
    ruleset: RuleSet = NO_EXTRA_RULES,
    *,
    extra_packs: Sequence[Path] = (),
    built_in: Sequence[BuiltInPack] | None = None,
) -> InForce:
    """The built-in rules less the switched-off ids, then each pack's rules.

    **Refuses an id that a built-in rule still in force has, or that another
    pack has**, naming both. Which of two rules sharing an id would win is not
    something a finding may depend on. Switching a built-in rule off frees its
    id, which is how a reader replaces one.

    An id in `switched_off` that no built-in rule has is ignored: a rule renamed
    in a later version leaves its old id in the reader's file.
    """
    packs = built_in_packs() if built_in is None else built_in
    rules: list[Rule] = []
    built_in_owner: dict[str, str] = {}
    switched: list[str] = []
    for pack in packs:
        for rule in pack.rules:
            if rule.id in ruleset.switched_off:
                switched.append(rule.id)
                continue
            built_in_owner[rule.id] = pack.name
            rules.append(rule)
    built_in_count = len(rules)

    added: list[tuple[str, list[Rule], bool]] = [
        (pack.name, load_pack_text(f"{pack.name}.yaml", pack.text), True) for pack in ruleset.packs
    ]
    if extra_packs:
        from_files: dict[str, list[Rule]] = {}
        for rule in load_rules(list(extra_packs)):
            from_files.setdefault(rule.source_pack, []).append(rule)
        added.extend((name, found, False) for name, found in from_files.items())

    pack_owner: dict[str, str] = {}
    for label, found, switchable in added:
        for rule in found:
            if rule.id in built_in_owner:
                raise _built_in_clash(rule.id, label, built_in_owner[rule.id], switchable)
            if rule.id in pack_owner:
                raise RulePackError(
                    f"rule {rule.id!r} in {label} has the same id as a rule in "
                    f"{pack_owner[rule.id]}; every rule needs an id of its own",
                    rule_id=rule.id,
                    reason=(
                        f"your {pack_owner[rule.id]} pack already has a rule with this id. "
                        "Every rule needs an id of its own."
                    ),
                )
            pack_owner[rule.id] = label
            rules.append(rule)

    described = plural(built_in_count, "built-in rule")
    if switched:
        described += f", {len(switched)} switched off ({', '.join(sorted(switched))})"
    if added:
        described += "; added: " + ", ".join(
            f"{label} ({plural(len(found), 'rule')})" for label, found, _ in added
        )
    return InForce(tuple(rules), described)


def _built_in_clash(rule_id: str, label: str, pack: str, switchable: bool) -> RulePackError:
    """A pack rule with a built-in rule's id. The window can switch the built-in
    off, so its message says so; the command line cannot, so its message does not."""
    reason = f"this id belongs to a built-in rule, in the {pack} pack. Give yours an id of its own"
    reason += ", or switch the built-in one off if yours replaces it." if switchable else "."
    return RulePackError(f"rule {rule_id!r} in {label}: {reason}", rule_id=rule_id, reason=reason)


def sort_out(
    packs: Sequence[PackText],
    switched_off: frozenset[str] = frozenset(),
    *,
    built_in: Sequence[BuiltInPack] | None = None,
) -> tuple[RuleSet, dict[str, RulePackError]]:
    """The packs that build together, in the order given, and why each other one does not.

    A pack is tried with the ones already kept, so of two that share an id the
    later one is left out and the message names the earlier. Each pack left out
    is the reader's to fix; the rest still apply.
    """
    loaded = built_in_packs() if built_in is None else tuple(built_in)
    kept: list[PackText] = []
    refused: dict[str, RulePackError] = {}
    for pack in packs:
        try:
            build_rules(RuleSet((*kept, pack), switched_off), built_in=loaded)
        except RulePackError as exc:
            refused[pack.name] = exc
        else:
            kept.append(pack)
    return RuleSet(tuple(kept), switched_off), refused
