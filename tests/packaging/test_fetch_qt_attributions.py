"""Which of Qt's attribution records the Windows bundle carries.

`packaging/fetch_qt_attributions.py` reads them from Qt's sources; this checks
the choice it makes, which is the part that decides what the bundle says.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def fetch() -> ModuleType:
    path = ROOT / "packaging" / "fetch_qt_attributions.py"
    spec = importlib.util.spec_from_file_location("logarc_fetch_qt_script", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a_component_of_a_shipped_module_is_kept(fetch: ModuleType) -> None:
    record = {"Id": "harfbuzz-ng", "QDocModule": "qtgui"}

    assert fetch.kept("src/3rdparty/harfbuzz-ng/qt_attribution.json", record)


def test_a_component_of_a_module_not_shipped_is_left_out(fetch: ModuleType) -> None:
    """Qt SQL is not in the bundle, so SQLite's notice would claim code it lacks."""
    record = {"Id": "sqlite", "QDocModule": "qtsql"}

    assert not fetch.kept("src/3rdparty/sqlite/qt_attribution.json", record)


def test_a_component_for_another_platform_is_left_out(fetch: ModuleType) -> None:
    record = {"Id": "xcb", "QDocModule": "qtgui"}

    assert not fetch.kept("src/3rdparty/xcb/qt_attribution.json", record)


def test_a_component_only_in_tools_or_tests_is_left_out(fetch: ModuleType) -> None:
    record = {"Id": "catch2", "QDocModule": "qtcore", "QtParts": ["tests"]}

    assert not fetch.kept("src/corelib/text/qt_attribution.json", record)


def test_records_with_raw_newlines_in_strings_are_read(fetch: ModuleType) -> None:
    """Qt writes some of its records that way, and strict JSON refuses them."""
    text = '{"Id": "ucd", "Description": "two\nlines", "QDocModule": "qtcore"}'

    (record,) = fetch._records(text)

    assert record["Id"] == "ucd"


def test_a_licence_file_named_relative_to_another_folder_is_found(fetch: ModuleType) -> None:
    """Qt GUI's painting record points at FreeType's licence by `../../`."""
    assert fetch.source_of("src/gui/painting", "../../3rdparty/freetype/LICENSE.txt") == (
        "src/3rdparty/freetype/LICENSE.txt"
    )


def test_a_record_s_own_licence_files_are_used(fetch: ModuleType) -> None:
    record = {"LicenseFiles": ["COPYING", "../other/NOTICE"], "LicenseId": "MIT"}

    assert fetch.licence_sources("src/3rdparty/thing", record, set()) == [
        "src/3rdparty/thing/COPYING",
        "src/3rdparty/other/NOTICE",
    ]


def test_a_record_naming_only_a_licence_id_takes_the_repository_s_text(
    fetch: ModuleType,
) -> None:
    """Qt keeps one text per SPDX id in each repository's LICENSES folder, and
    Wintab and Emoji Segmenter, both in the shipped DLLs, name only an id."""
    available = {"LICENSES/Apache-2.0.txt", "LICENSES/FTL.txt", "LICENSES/GPL-2.0-only.txt"}

    assert fetch.licence_sources("src/3rdparty/emoji", {"LicenseId": "Apache-2.0"}, available) == [
        "LICENSES/Apache-2.0.txt"
    ]
    assert fetch.licence_sources("x", {"LicenseId": "FTL OR GPL-2.0-only"}, available) == [
        "LICENSES/FTL.txt",
        "LICENSES/GPL-2.0-only.txt",
    ]


def test_a_record_with_no_licence_text_anywhere_stops_the_fetch(fetch: ModuleType) -> None:
    with pytest.raises(fetch.QtAttributionError, match="Mystery"):
        fetch.licence_sources("x", {"Name": "Mystery", "LicenseId": "Nowhere-1.0"}, set())


def test_every_committed_qt_notice_carries_its_licence_text() -> None:
    """The bundle ships this file as it is, so a component listed without the
    text of its licence is the omission the fetch exists to prevent."""
    folder = ROOT / "packaging" / "qt-attributions"
    notices = (folder / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    blocks = [block for block in notices.split("\n\n") if "Recorded in:" in block]

    assert blocks
    for block in blocks:
        name = block.splitlines()[0]
        (texts,) = [line for line in block.splitlines() if line.startswith("Licence text: ")]
        for path in texts.removeprefix("Licence text: ").split("; "):
            assert (folder / path).is_file(), f"{name}: {path} is missing"


#: Components known to be compiled into the Qt files the bundle ships. A floor,
#: not the list: dropping any of these from the committed notices fails here.
_COMPILED_IN = (
    "HarfBuzz-NG",
    "Freetype 2",
    "LibPNG",
    "LibJPEG-turbo",
    "Data Compression Library (zlib)",
    "PCRE2",
    "Wintab API",
    "Emoji Segmenter",
    "Unicode Character Database (UCD)",
    "XSVG",
    "WebP",
    "LibTIFF",
)


def test_the_committed_qt_notices_name_what_is_compiled_in() -> None:
    notices = (ROOT / "packaging" / "qt-attributions" / "THIRD-PARTY-NOTICES.txt").read_text(
        encoding="utf-8"
    )
    names = {block.splitlines()[0] for block in notices.split("\n\n") if "Recorded in:" in block}

    missing = [name for name in _COMPILED_IN if not any(name.lower() in n.lower() for n in names)]
    assert not missing, f"not in the Qt notices: {missing}"


def test_the_fetch_writes_each_kept_component_with_its_licence_text(
    fetch: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end against a stand-in for Qt's sources: one component with its
    own licence file, one naming only an SPDX id, and one for another module."""
    import json

    tree = {
        "tree": [
            {"path": "LICENSES/Apache-2.0.txt"},
            {"path": "src/3rdparty/own/qt_attribution.json"},
            {"path": "src/3rdparty/byid/qt_attribution.json"},
            {"path": "src/3rdparty/sql/qt_attribution.json"},
        ]
    }
    files = {
        "src/3rdparty/own/qt_attribution.json": json.dumps(
            {"Name": "Own", "QDocModule": "qtgui", "LicenseFile": "COPYING"}
        ),
        "src/3rdparty/own/COPYING": "own terms",
        "src/3rdparty/byid/qt_attribution.json": json.dumps(
            {"Name": "ById", "QDocModule": "qtcore", "LicenseId": "Apache-2.0"}
        ),
        "LICENSES/Apache-2.0.txt": "apache terms",
        "src/3rdparty/sql/qt_attribution.json": json.dumps(
            {"Name": "Sql", "QDocModule": "qtsql", "LicenseFile": "LICENSE"}
        ),
    }

    def get(url: str) -> bytes:
        if "/commits/" in url:
            return b'{"sha": "abc"}'
        if "/git/trees/" in url:
            return json.dumps(tree).encode()
        return files[url.split("/abc/", 1)[1]].encode()

    monkeypatch.setattr(fetch, "_get", get)
    monkeypatch.setattr(fetch, "REPOSITORIES", ("qtbase",))
    monkeypatch.setattr(fetch, "OUT", tmp_path / "out")

    fetch.fetch("v6.11.1")

    notices = (tmp_path / "out" / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    assert "Own\n" in notices and "ById\n" in notices
    assert "Sql" not in notices
    assert (tmp_path / "out" / "licenses" / "qtbase-src-3rdparty-own-COPYING").read_text() == (
        "own terms"
    )
    assert (tmp_path / "out" / "licenses" / "qtbase-LICENSES-Apache-2.0.txt").read_text() == (
        "apache terms"
    )
    assert (tmp_path / "out" / "VERSION").read_text().strip() == "6.11.1"
