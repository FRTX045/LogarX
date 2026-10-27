"""The rule packs a reader keeps in their settings, beside their saved formats."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logarx import rules_library
from logarx.core.activity import ActivityCategory, Severity
from logarx.detect.rules import RulePackError, load_pack_text
from logarx.detect.ruleset import PackText
from logarx.parsers.library import logarx_home
from logarx.rule_draft import Condition, Draft, Test, rule_block

HOUSE = """\
version: 1
note: Our own CGI scripts
rules:
  - id: house_cgi_probe
    name: House rule CGI probe
    category: injection
    severity: high
    match:
      any:
        - {field: path_decoded, regex: "/cgi-bin/quux"}
"""


def _with_id(rule_id: str) -> str:
    return HOUSE.replace("house_cgi_probe", rule_id)


def test_packs_live_beside_the_saved_formats() -> None:
    assert rules_library.rules_dir() == logarx_home() / "rules"


def test_a_saved_pack_is_a_yaml_file_the_reader_can_open() -> None:
    path = rules_library.save_pack("house", HOUSE)

    assert path == rules_library.rules_dir() / "house.yaml"
    assert path.read_text(encoding="utf-8") == HOUSE


def test_a_saved_pack_is_in_force_with_its_note() -> None:
    rules_library.save_pack("house", HOUSE)

    library = rules_library.in_force()

    assert library.ruleset.packs == (PackText("house", HOUSE),)
    assert [(p.name, p.note, p.problem) for p in library.packs] == [
        ("house", "Our own CGI scripts", "")
    ]


def test_a_pack_that_does_not_load_is_refused_at_save_and_nothing_is_written() -> None:
    with pytest.raises(RulePackError):
        rules_library.save_pack("house", "version: 1\nrules:\n  - id: x\n")

    assert not (rules_library.rules_dir() / "house.yaml").exists()


@pytest.mark.parametrize(
    ("name", "problem"),
    [
        ("", "A pack needs a name."),
        ("my rules", "A name can hold letters, digits, - and _ only."),
        ("über", "A name can hold letters, digits, - and _ only."),
    ],
)
def test_a_name_is_a_file_name(name: str, problem: str) -> None:
    assert rules_library.name_problem(name) == problem


def test_a_name_differing_only_in_case_is_taken() -> None:
    """Windows keeps one file for `Shop.yaml` and `shop.yaml`; saving the second
    would overwrite the first."""
    rules_library.save_pack("Shop", HOUSE)

    assert rules_library.name_problem("shop") == "You already have a pack called Shop."
    with pytest.raises(rules_library.RulesLibraryError):
        rules_library.save_pack("shop", _with_id("other_rule"))
    assert (rules_library.rules_dir() / "Shop.yaml").read_text(encoding="utf-8") == HOUSE


def test_saving_under_a_new_name_renames_the_pack() -> None:
    rules_library.save_pack("house", HOUSE)

    rules_library.save_pack("cgi", HOUSE, replacing="house")

    assert [p.name for p in rules_library.in_force().packs] == ["cgi"]


def test_a_pack_may_keep_its_own_name_when_saved_again() -> None:
    rules_library.save_pack("house", HOUSE)

    assert rules_library.name_problem("house", replacing="house") == ""
    rules_library.save_pack("house", _with_id("house_cgi_probe_2"), replacing="house")


def test_saving_a_pack_that_clashes_with_another_is_refused() -> None:
    rules_library.save_pack("house", HOUSE)

    with pytest.raises(RulePackError, match="house"):
        rules_library.save_pack("again", HOUSE)


def test_a_deleted_pack_stops_applying() -> None:
    rules_library.save_pack("house", HOUSE)

    rules_library.delete_pack("house")

    assert rules_library.in_force().ruleset.packs == ()


def test_of_two_packs_sharing_an_id_the_later_one_is_left_out() -> None:
    """Written by hand, outside the app: both files load alone."""
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "alpha.yaml").write_text(HOUSE, encoding="utf-8")
    (folder / "beta.yaml").write_text(HOUSE, encoding="utf-8")

    library = rules_library.in_force()

    assert [p.name for p in library.ruleset.packs] == ["alpha"]
    assert "alpha" in library.refused["beta"]
    assert (folder / "beta.yaml").read_text(encoding="utf-8") == HOUSE  # never rewritten


def test_a_pack_that_cannot_be_read_is_listed_as_not_loading() -> None:
    """Not as an empty pack that quietly applies nothing."""
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "garbled.yaml").write_bytes(b"\xff\xfe\x00not text")

    library = rules_library.in_force()

    assert library.ruleset.packs == ()
    assert "could not be read" in library.refused["garbled"]


def test_a_pack_broken_on_disk_is_listed_with_its_error_and_left_out() -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "broken.yaml").write_text("version: 1\nrules:\n  - id: x\n", encoding="utf-8")
    rules_library.save_pack("house", HOUSE)

    library = rules_library.in_force()

    assert [p.name for p in library.ruleset.packs] == ["house"]
    assert library.refused["broken"]


def test_switched_off_ids_round_trip_as_a_sorted_list() -> None:
    rules_library.switch_rule("sqli_union_select", on=False)
    rules_library.switch_rule("http_library_user_agent", on=False)

    stored = json.loads((rules_library.rules_dir() / "switched-off.json").read_text("utf-8"))

    assert stored == ["http_library_user_agent", "sqli_union_select"]
    assert rules_library.in_force().ruleset.switched_off == frozenset(stored)


def test_switching_a_rule_back_on_removes_it_and_keeps_unknown_ids() -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "switched-off.json").write_text('["renamed_long_ago", "sqli_union_select"]')

    rules_library.switch_rule("sqli_union_select", on=True)

    assert rules_library.switched_off() == frozenset({"renamed_long_ago"})


def test_a_damaged_switch_file_turns_nothing_off_and_says_so() -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "switched-off.json").write_text("{not json")

    library = rules_library.in_force()

    assert library.ruleset.switched_off == frozenset()
    assert "switched-off.json" in library.trouble


def test_switching_a_built_in_back_on_leaves_out_the_pack_that_took_its_id() -> None:
    rules_library.switch_rule("sqli_union_select", on=False)
    rules_library.save_pack("replacement", _with_id("sqli_union_select"))

    rules_library.switch_rule("sqli_union_select", on=True)
    library = rules_library.in_force()

    assert library.ruleset.packs == ()
    assert "built-in" in library.refused["replacement"]


@pytest.mark.parametrize(
    ("stem", "name"), [("My Rules", "My-Rules"), ("shop.v2", "shop-v2"), ("ok_1", "ok_1")]
)
def test_a_loaded_file_s_name_becomes_a_pack_name(stem: str, name: str) -> None:
    assert rules_library.file_name_for(stem) == name


def test_loading_a_file_copies_it_into_the_library(tmp_path: Path) -> None:
    source = tmp_path / "My Rules.yaml"
    source.write_text(HOUSE, encoding="utf-8")

    assert rules_library.import_pack(source) == "My-Rules"
    assert (rules_library.rules_dir() / "My-Rules.yaml").read_text(encoding="utf-8") == HOUSE


def test_loading_a_file_that_does_not_load_copies_nothing(tmp_path: Path) -> None:
    source = tmp_path / "bad.yaml"
    source.write_text("version: 1\nrules:\n  - id: x\n", encoding="utf-8")

    with pytest.raises(RulePackError):
        rules_library.import_pack(source)

    assert not rules_library.rules_dir().exists() or not list(rules_library.rules_dir().iterdir())


def test_loading_a_file_whose_name_is_taken_is_refused(tmp_path: Path) -> None:
    rules_library.save_pack("house", HOUSE)
    source = tmp_path / "House.yaml"
    source.write_text(_with_id("other_rule"), encoding="utf-8")

    with pytest.raises(rules_library.RulesLibraryError, match="house"):
        rules_library.import_pack(source)


def test_an_empty_folder_and_a_missing_one_are_both_no_packs() -> None:
    assert rules_library.in_force().ruleset.packs == ()
    rules_library.rules_dir().mkdir(parents=True)
    assert rules_library.in_force().ruleset.packs == ()


def test_renaming_a_pack_only_in_its_capitals_keeps_it() -> None:
    """Windows keeps one file for `Shop.yaml` and `shop.yaml`. Saving under the
    new name and then deleting the old one deleted the pack just saved, and a
    pack the reader wrote exists nowhere else."""
    rules_library.save_pack("Shop", HOUSE)

    rules_library.save_pack("shop", _with_id("other_rule"), replacing="Shop")

    assert [(p.name, p.text) for p in rules_library.in_force().packs] == [
        ("shop", _with_id("other_rule"))
    ]


# -- adding one rule from the Add a rule window -------------------------------


def _block(rule_id: str = "added") -> str:
    draft = Draft(
        name="Added",
        category=ActivityCategory.INJECTION,
        severity=Severity.HIGH,
        mode="all",
        conditions=(Condition("path", Test.EQUALS, "/added"),),
    )
    return rule_block(draft, rule_id)


def _ids(name: str) -> list[str]:
    text = (rules_library.rules_dir() / f"{name}.yaml").read_text(encoding="utf-8")
    return [rule.id for rule in load_pack_text("t.yaml", text)]


def test_a_rule_is_added_to_the_end_of_a_pack() -> None:
    rules_library.save_pack("shop", HOUSE)

    rules_library.add_rule(rules_library.Target("shop", True), _block(), started_from=HOUSE)

    assert _ids("shop") == ["house_cgi_probe", "added"]
    written = (rules_library.rules_dir() / "shop.yaml").read_text(encoding="utf-8")
    assert written.startswith(HOUSE)


def test_the_first_rule_creates_my_rules() -> None:
    target = rules_library.target_for(rules_library.in_force(), None)

    assert target == rules_library.Target("My-rules", False)
    rules_library.add_rule(target, _block(), started_from="")
    written = (rules_library.rules_dir() / "My-rules.yaml").read_text(encoding="utf-8")
    assert written.startswith(rules_library.NEW_PACK_HEAD)
    assert _ids("My-rules") == ["added"]


def test_a_pack_changed_elsewhere_is_not_overwritten() -> None:
    rules_library.save_pack("shop", HOUSE)
    changed = HOUSE.replace("Our own CGI scripts", "Edited elsewhere")
    (rules_library.rules_dir() / "shop.yaml").write_text(changed, encoding="utf-8")

    with pytest.raises(rules_library.RulesLibraryError) as raised:
        rules_library.add_rule(rules_library.Target("shop", True), _block(), started_from=HOUSE)

    assert str(raised.value) == "shop was changed outside this window. Close it and try again."
    assert (rules_library.rules_dir() / "shop.yaml").read_text(encoding="utf-8") == changed


def test_a_pack_deleted_meanwhile_is_said() -> None:
    rules_library.save_pack("shop", HOUSE)
    (rules_library.rules_dir() / "shop.yaml").unlink()

    with pytest.raises(rules_library.RulesLibraryError) as raised:
        rules_library.add_rule(rules_library.Target("shop", True), _block(), started_from=HOUSE)

    assert str(raised.value) == (
        "shop is no longer in your rules folder. Close this window and try again."
    )
    assert not (rules_library.rules_dir() / "shop.yaml").exists()


def test_a_pack_that_cannot_be_read_is_said() -> None:
    rules_library.save_pack("shop", HOUSE)
    (rules_library.rules_dir() / "shop.yaml").write_bytes(b"version: 1\n\xff\xfe\n")

    with pytest.raises(rules_library.RulesLibraryError) as raised:
        rules_library.add_rule(rules_library.Target("shop", True), _block(), started_from=HOUSE)

    assert str(raised.value).startswith("shop.yaml could not be read:")


def test_a_broken_my_rules_in_any_case_is_never_replaced() -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "my-rules.yaml").write_bytes(b"rules: [oops")

    target = rules_library.target_for(rules_library.in_force(), None)

    assert target.problem == (
        "A pack called my-rules exists but does not load. "
        "Pick another pack, or fix that one in the YAML editor."
    )
    with pytest.raises(rules_library.RulesLibraryError, match="my-rules exists"):
        rules_library.add_rule(target, _block(), started_from="")
    assert (folder / "my-rules.yaml").read_bytes() == b"rules: [oops"
    assert sorted(path.name for path in folder.iterdir()) == ["my-rules.yaml"]


def test_the_preferred_pack_is_the_target_when_it_loads() -> None:
    rules_library.save_pack("a", HOUSE)
    rules_library.save_pack("b", _with_id("other"))
    (rules_library.rules_dir() / "c.yaml").write_text("rules: [oops", encoding="utf-8")
    library = rules_library.in_force()

    assert rules_library.target_for(library, "b") == rules_library.Target("b", True)
    assert rules_library.target_for(library, "c") == rules_library.Target("My-rules", False)


def test_an_existing_my_rules_in_other_capitals_is_used() -> None:
    rules_library.save_pack("my-RULES", HOUSE)

    target = rules_library.target_for(rules_library.in_force(), None)

    assert target == rules_library.Target("my-RULES", True)


def test_an_id_clash_with_another_pack_is_refused() -> None:
    rules_library.save_pack("a", HOUSE)
    rules_library.save_pack("b", _with_id("other"))
    text_b = (rules_library.rules_dir() / "b.yaml").read_text(encoding="utf-8")

    with pytest.raises(RulePackError):
        rules_library.add_rule(
            rules_library.Target("b", True), _block("house_cgi_probe"), started_from=text_b
        )

    assert (rules_library.rules_dir() / "b.yaml").read_text(encoding="utf-8") == text_b
