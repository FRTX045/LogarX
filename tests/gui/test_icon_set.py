"""The shipped icon set, the default icon for each kind, and the names icons go by.

Qt-free on purpose: which icon a kind gets, and whether a name means anything,
are facts about data. Drawing them is `test_icons.py`'s business.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from logarc.core.activity import ActivityCategory
from logarc.gui import icon_set
from logarc.gui.icon_set import (
    DEFAULT_ICONS,
    KIND_NAMES,
    LUCIDE_VERSION,
    file_name_of,
    icons_dir,
    is_known,
    lucide,
    search,
)
from logarc.gui.rule_form_view import CATEGORY_LABELS

DATA = Path(icon_set.__file__).with_name("lucide.json")
TOOL = Path(__file__).parents[2] / "tools" / "lucide_data.py"


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lucide_data", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_kind_has_a_shipped_icon() -> None:
    assert set(DEFAULT_ICONS) == set(ActivityCategory)
    assert all(name in lucide() for name in DEFAULT_ICONS.values())


def test_the_defaults_are_the_spec_table() -> None:
    assert dict(DEFAULT_ICONS) == {
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


def test_the_set_is_the_pinned_version_whole() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    assert data["version"] == LUCIDE_VERSION == "0.452.0"
    assert data["source"] == "lucide-static@0.452.0"
    assert set(data["sha256"]) == {"icon-nodes.json", "tags.json"}
    assert len(lucide()) == 1533


def test_an_icon_is_a_lucide_frame_around_its_shapes() -> None:
    syringe = lucide()["syringe"]
    assert syringe.svg.startswith('<svg xmlns="http://www.w3.org/2000/svg" width="24"')
    assert 'stroke="currentColor"' in syringe.svg
    assert '<path d="m18 2 4 4"/>' in syringe.svg
    assert syringe.svg.endswith("</svg>")
    assert "needle" in syringe.tags


def test_kind_names_are_the_windows_plus_unknown() -> None:
    assert dict(KIND_NAMES) == {**CATEGORY_LABELS, ActivityCategory.UNKNOWN: "Unknown"}
    assert list(KIND_NAMES) == list(ActivityCategory)


def test_search_ranks_names_before_tags() -> None:
    found = search("needle")
    assert "syringe" in found, "found by its tag"
    assert search("key")[0] == "key", "the exact name first"
    names_first = search("lock")
    assert names_first.index("lock") < names_first.index("key-round"), "a name before a tag"
    assert search("") == sorted(lucide())


def test_search_wants_every_word() -> None:
    assert "lock-open" in search("lock open")
    assert "lock" not in search("lock open")


@pytest.mark.parametrize(
    "value", ["file:../x.svg", "file:a/b.png", "file:a\\b.png", "file:", "file:..", "skull"]
)
def test_only_a_bare_file_name_is_a_file_value(value: str) -> None:
    assert file_name_of(value) is None


def test_a_bare_file_name_is_read_back() -> None:
    assert file_name_of("file:logo.svg") == "logo.svg"


def test_a_file_value_is_known_only_while_its_file_exists() -> None:
    icons_dir().mkdir(parents=True)
    (icons_dir() / "logo.svg").write_text("<svg/>", encoding="utf-8")
    assert is_known("file:logo.svg")
    assert not is_known("file:gone.svg")
    assert not is_known("file:../logo.svg")
    assert is_known("skull")
    assert not is_known("skul")


def test_the_reader_icons_live_beside_their_rules(tmp_path: Path) -> None:
    from logarc.parsers.library import logarc_home

    assert icons_dir() == logarc_home() / "icons"


def test_the_builder_frames_and_records(tmp_path: Path) -> None:
    nodes = tmp_path / "icon-nodes.json"
    tags = tmp_path / "tags.json"
    nodes.write_text(
        json.dumps(
            {
                "dot": [["path", {"d": "M1 1h2"}], ["circle", {"cx": "12", "cy": "12", "r": "1"}]],
                "amp": [["path", {"d": 'a&b"c'}]],
            }
        ),
        encoding="utf-8",
    )
    tags.write_text(json.dumps({"dot": ["point"], "amp": []}), encoding="utf-8")

    data = _tool().build(nodes, tags)

    dot = data["icons"]["dot"]
    assert dot["svg"].startswith(
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        'stroke-linejoin="round">'
    )
    assert dot["svg"].endswith('<path d="M1 1h2"/><circle cx="12" cy="12" r="1"/></svg>')
    assert dot["tags"] == ["point"]
    assert '<path d="a&amp;b&quot;c"/>' in data["icons"]["amp"]["svg"]
    assert data["version"] == "0.452.0"
    assert data["source"] == "lucide-static@0.452.0"
    assert data["sha256"]["tags.json"] == hashlib.sha256(tags.read_bytes()).hexdigest()
    assert data["sha256"]["icon-nodes.json"] == hashlib.sha256(nodes.read_bytes()).hexdigest()


MINE = """\
version: 1
rules:
  - id: mine_rule
    name: Mine
    category: injection
    severity: high
    icon: skull
    match:
      any:
        - {field: path, contains: "/mine"}
  - id: plain_rule
    name: Plain
    category: browsing
    severity: info
    match:
      any:
        - {field: path, contains: "/plain"}
"""


def test_rule_icons_reads_the_readers_packs() -> None:
    from logarc.detect.ruleset import PackText, RuleSet
    from logarc.gui.icon_set import rule_icons

    assert rule_icons(RuleSet((PackText("mine", MINE),))) == {"mine_rule": "skull"}


def test_a_pack_that_does_not_load_gives_no_icons() -> None:
    from logarc.detect.ruleset import PackText, RuleSet
    from logarc.gui.icon_set import rule_icons

    broken = PackText("broken", "version: 1\nrules: [nonsense")
    assert rule_icons(RuleSet((broken, PackText("mine", MINE)))) == {"mine_rule": "skull"}


def test_unknown_icons_are_named_once_each_in_rule_order() -> None:
    from logarc.detect.rules import load_pack_text
    from logarc.gui.icon_set import unknown_icons

    text = MINE.replace("icon: skull", "icon: skul").replace(
        "    severity: info\n", "    severity: info\n    icon: file:../x.svg\n"
    )
    rules = load_pack_text("mine.yaml", text) + load_pack_text(
        "again.yaml", text.replace("_rule", "_2")
    )
    assert unknown_icons(rules) == ["skul", "file:../x.svg"]


def test_the_unknown_icon_note() -> None:
    from logarc.gui.icon_set import unknown_icon_note

    assert unknown_icon_note([]) == ""
    assert unknown_icon_note(["skul"]) == (
        "Icon skul is not one logarc knows, so its kind's icon is drawn."
    )
    assert unknown_icon_note(["skul", "file:x.svg"]) == (
        "Icons skul and file:x.svg are not ones logarc knows, so their kinds' icons are drawn."
    )
