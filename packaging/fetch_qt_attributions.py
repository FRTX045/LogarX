"""Fetch the third-party attributions of the Qt the Windows bundle ships.

The Qt wheel carries Qt's own LGPL text and nothing about the components Qt
compiles in: HarfBuzz, FreeType, libpng, zlib, PCRE2 and the rest. Qt records
each of them in a `qt_attribution.json` beside its source, so this reads those
records from Qt's sources at the version installed here and writes what the
bundle has to carry into `packaging/qt-attributions/`, which is committed:

    .venv\\Scripts\\python.exe packaging\\fetch_qt_attributions.py

Run it again when the PyQt6-Qt6 version changes. `licences.py` refuses a
bundle whose Qt version differs from the one recorded here, so a Qt upgrade
cannot ship the previous version's notices. Needs the network; the build does
not.

A record is kept when it names a Qt module the bundle ships and is not for a
platform the Windows bundle never runs on. Where that leaves a doubt (Pixman,
used on ARM only) the record is kept: a notice the bundle does not strictly
need costs nothing, and a missing one is the failure this exists to prevent.
"""

from __future__ import annotations

import json
import posixpath
import re
import shutil
import sys
import urllib.request
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, Final

ROOT: Final = Path(__file__).resolve().parents[1]
OUT: Final = ROOT / "packaging" / "qt-attributions"

#: The Qt repositories the shipped libraries and plugins are built from:
#: Core, Gui, Widgets and the platform, style, JPEG and GIF plugins from
#: qtbase, Svg with its image and icon plugins from qtsvg, and the WebP, TIFF,
#: TGA, WBMP and ICNS image plugins from qtimageformats.
REPOSITORIES: Final = ("qtbase", "qtsvg", "qtimageformats")

#: The Qt modules the bundle ships, as `QDocModule` names them.
SHIPPED: Final = frozenset({"qtcore", "qtgui", "qtwidgets", "qtsvg", "qtimageformats"})

#: Folders whose records are for platforms or tooling the Windows bundle never
#: contains, whatever module they name.
_ELSEWHERE: Final = (
    "cmake/",
    "util/",
    "src/testlib/",
    "src/testinternal/",
    "src/3rdparty/android/",
    "src/3rdparty/gradle/",
    "src/3rdparty/wasm/",
    "src/3rdparty/wayland/",
    "src/3rdparty/xcb/",
    "src/3rdparty/forkfd/",
    "src/plugins/platforms/cocoa/",
)


class QtAttributionError(RuntimeError):
    """A component the bundle ships has no licence text to be found."""


#: The words of an SPDX expression that are not licence ids.
_SPDX_WORDS: Final = frozenset({"AND", "OR", "WITH"})


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return bytes(response.read())


def _records(text: str) -> list[dict[str, Any]]:
    # Lenient: several of Qt's records carry raw newlines inside strings.
    data = json.loads(text, strict=False)
    return data if isinstance(data, list) else [data]


def kept(path: str, record: dict[str, Any]) -> bool:
    """Whether the record at `path` describes code the bundle ships."""
    if path.startswith(_ELSEWHERE):
        return False
    if "libs" not in record.get("QtParts", ["libs"]):
        return False
    return record.get("QDocModule") in SHIPPED


def source_of(folder: str, name: str) -> str:
    """Where a record in `folder` finds the file it names, which may be in
    another folder: Qt GUI's painting record names FreeType's licence by `../../`."""
    return posixpath.normpath(f"{folder}/{name}")


def licence_sources(folder: str, record: dict[str, Any], available: set[str]) -> list[str]:
    """The repository paths of the licence texts a record in `folder` points at.

    Its own `LicenseFile`, `LicenseFiles` and `CopyrightFile` when it names
    any. Otherwise Qt's rule: each SPDX id in its `LicenseId` has its text in
    the repository's `LICENSES/<id>.txt`, which `available` lists. Raises
    rather than returning nothing, so no component is written without its text.
    """
    named = (
        _names(record.get("LicenseFile"))
        + _names(record.get("LicenseFiles"))
        + _names(record.get("CopyrightFile"))
    )
    if named:
        return [source_of(folder, name) for name in named]
    ids = [
        word
        for word in re.split(r"[\s()]+", str(record.get("LicenseId", "")))
        if word and word not in _SPDX_WORDS
    ]
    found = [f"LICENSES/{licence}.txt" for licence in ids if f"LICENSES/{licence}.txt" in available]
    if not found or len(found) != len(ids):
        name = record.get("Name", record.get("Id"))
        raise QtAttributionError(f"{name}: no licence text for {record.get('LicenseId')!r}")
    return found


def _names(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _line(label: str, value: Any) -> str:
    if value is None:
        return ""
    text = "; ".join(value) if isinstance(value, list) else str(value)
    return f"{label}: {text}\n"


def fetch(tag: str) -> list[str]:
    """Write the attributions for `tag` into `OUT`; return what it says."""
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "licenses").mkdir(parents=True)
    notices: list[str] = []
    sources: list[str] = []
    for repository in REPOSITORIES:
        commit = json.loads(_get(f"https://api.github.com/repos/qt/{repository}/commits/{tag}"))[
            "sha"
        ]
        sources.append(f"qt/{repository} {tag} {commit}")
        tree = json.loads(
            _get(f"https://api.github.com/repos/qt/{repository}/git/trees/{commit}?recursive=1")
        )
        raw = f"https://raw.githubusercontent.com/qt/{repository}/{commit}"
        available = {item["path"] for item in tree["tree"]}
        for entry in sorted(tree["tree"], key=lambda item: item["path"]):
            if not entry["path"].endswith("qt_attribution.json"):
                continue
            here = PurePosixPath(entry["path"]).parent
            for record in _records(_get(f"{raw}/{entry['path']}").decode("utf-8")):
                if not kept(entry["path"], record):
                    continue
                files = []
                for path in licence_sources(here.as_posix(), record, available):
                    target = f"{repository}-{'-'.join(PurePosixPath(path).parts)}"
                    if not (OUT / "licenses" / target).exists():
                        (OUT / "licenses" / target).write_bytes(_get(f"{raw}/{path}"))
                    files.append(f"licenses/{target}")
                notices.append(
                    f"{record.get('Name', record.get('Id'))}\n"
                    + _line("Version", record.get("Version"))
                    + _line("Used in", record.get("QtUsage"))
                    + _line("Licence", record.get("License"))
                    + _line("Copyright", record.get("Copyright"))
                    + _line("Licence text", files or None)
                    + f"Recorded in: qt/{repository} {entry['path']}\n"
                )
    header = (
        f"Third-party components of the Qt {tag.removeprefix('v')} libraries this bundle ships\n"
        "(Qt Core, Qt GUI, Qt Widgets, Qt SVG and the Qt Image Formats plugins), as Qt's own\n"
        "qt_attribution.json records "
        "list them. Qt itself is under the LGPL; its text is in ../python/pyqt6-qt6.\n\n"
        + "".join(f"Source: {line}\n" for line in sources)
        + "\n"
    )
    (OUT / "THIRD-PARTY-NOTICES.txt").write_text(
        header + "\n".join(notices), encoding="utf-8", newline="\n"
    )
    (OUT / "VERSION").write_text(tag.removeprefix("v") + "\n", encoding="utf-8", newline="\n")
    return notices


def main() -> int:
    tag = "v" + metadata.version("PyQt6-Qt6")
    notices = fetch(tag)
    print(f"{len(notices)} components recorded for Qt {tag} in {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
