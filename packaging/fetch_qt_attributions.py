"""Fetch the third-party attributions of the Qt the Windows bundle ships.

The Qt wheel carries Qt's own LGPL text and nothing about the components Qt
compiles in: HarfBuzz, FreeType, libpng, zlib, PCRE2 and the rest. Qt records
each of them in a `qt_attribution.json` beside its source, so this reads those
records from Qt's sources at the version installed here and writes what the
bundle has to carry into `packaging/third-party/qt/`, which is committed:

    .venv\\Scripts\\python.exe packaging\\fetch_qt_attributions.py

Run it again when the PyQt6-Qt6 version changes. `rebuild.py` refuses a
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
OUT: Final = ROOT / "packaging" / "third-party" / "qt"

#: The Qt repositories the shipped libraries and plugins are built from:
#: Core, Gui, Widgets and the platform, style, JPEG and GIF plugins from
#: qtbase, Svg with its image and icon plugins from qtsvg, and the WebP, TIFF,
#: TGA, WBMP and ICNS image plugins from qtimageformats.
REPOSITORIES: Final = ("qtbase", "qtsvg", "qtimageformats")

#: The Qt modules the bundle ships, as `QDocModule` names them. Qt Network is
#: among them: PyInstaller collects it with the rest of the Qt wheel.
SHIPPED: Final = frozenset({"qtcore", "qtgui", "qtwidgets", "qtnetwork", "qtsvg", "qtimageformats"})

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


#: Shipped in the Qt wheel but built outside the repositories above, so no
#: `qt_attribution.json` there records them. `opengl32sw.dll`, the software
#: OpenGL renderer, is Mesa's llvmpipe with LLVM linked in, at the versions its
#: own strings name; Qt publishes no record for it. Each entry: name, version,
#: licence, where its text is, the file it is written to.
OPENGL32SW: Final = (
    (
        "Mesa 3D Graphics Library (llvmpipe), as opengl32sw.dll",
        "11.2.2",
        "MIT for the core library; the page lists the licence of each component",
        "https://gitlab.freedesktop.org/mesa/mesa/-/raw/mesa-11.2.2/docs/license.html",
        "mesa-11.2.2-license.html",
    ),
    (
        "LLVM, linked into opengl32sw.dll",
        "3.6.2",
        "University of Illinois/NCSA Open Source License",
        "https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-3.6.2/llvm/LICENSE.TXT",
        "llvm-3.6.2-LICENSE.txt",
    ),
)

#: The libraries PDFium links from Chromium's own third_party folder, outside
#: PDFium's tree, as its build names them.
PDFIUM_FROM_CHROMIUM: Final = ("freetype", "libjpeg_turbo", "libpng", "zlib", "abseil-cpp", "icu")

#: The file names a licence or notice goes by in PDFium's tree.
_LICENCE_FILE: Final = re.compile(r"(?i)^(license|licence|copying|notice|patents)([._-].*)?$")


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


def _tree(repository: str, ref: str) -> dict[str, Any]:
    url = f"https://api.github.com/repos/qt/{repository}/git/trees/{ref}"
    return dict(json.loads(_get(url)))


def _child(tree: dict[str, Any], name: str) -> dict[str, Any]:
    return dict(next(entry for entry in tree["tree"] if entry["path"] == name))


def pdfium_licences(paths: list[str]) -> list[str]:
    """The licence files in PDFium's tree: its own, and each third-party
    library's, however deep. Tests and their fonts are not shipped."""
    return [
        path
        for path in paths
        if _LICENCE_FILE.match(PurePosixPath(path).name)
        and not path.startswith(("testing/", "third_party/test"))
    ]


def fetch_pdfium(tag: str) -> tuple[list[str], str]:
    """PDFium, which Qt PDF is built on, from the Chromium snapshot `tag`'s
    qtwebengine pins: its licence and those of the third-party code in it."""
    snapshot = _child(
        _tree("qtwebengine", _child(_tree("qtwebengine", tag), "src")["sha"]), "3rdparty"
    )
    tree = _tree("qtwebengine-chromium", snapshot["sha"])
    for part in ("chromium", "third_party"):
        tree = _tree("qtwebengine-chromium", _child(tree, part)["sha"])
    chromium_third_party = tree
    tree = _tree("qtwebengine-chromium", _child(tree, "pdfium")["sha"])
    whole = _tree("qtwebengine-chromium", f"{tree['sha']}?recursive=1")
    raw = (
        f"https://raw.githubusercontent.com/qt/qtwebengine-chromium/{snapshot['sha']}"
        "/chromium/third_party/pdfium"
    )
    found = pdfium_licences([entry["path"] for entry in whole["tree"] if entry["type"] == "blob"])
    if not found:
        raise QtAttributionError("PDFium: no licence text found in its tree")
    files = []
    for path in found:
        target = "pdfium-" + "-".join(PurePosixPath(path).parts)
        (OUT / "licenses" / target).write_bytes(_get(f"{raw}/{path}"))
        files.append(f"licenses/{target}")
    for library in PDFIUM_FROM_CHROMIUM:
        folder = _tree(
            "qtwebengine-chromium", _child(chromium_third_party, library)["sha"] + "?recursive=1"
        )
        near = [
            entry["path"]
            for entry in folder["tree"]
            if entry["type"] == "blob"
            and entry["path"].count("/") <= 1
            and _LICENCE_FILE.match(PurePosixPath(entry["path"]).name)
        ]
        if not near:
            raise QtAttributionError(f"{library}, which PDFium links: no licence text found")
        base = (
            f"https://raw.githubusercontent.com/qt/qtwebengine-chromium/{snapshot['sha']}"
            f"/chromium/third_party/{library}"
        )
        for path in near:
            target = f"pdfium-chromium-{library}-" + "-".join(PurePosixPath(path).parts)
            (OUT / "licenses" / target).write_bytes(_get(f"{base}/{path}"))
            files.append(f"licenses/{target}")
    notice = (
        "PDFium, the third-party code in its tree, and the Chromium libraries it links\n"
        + "Used in: Qt PDF, which renders PDF images and documents\n"
        + "Licence: BSD 3-clause for PDFium; each third-party library's own licence\n"
        + _line("Licence text", files)
        + f"Recorded in: qt/qtwebengine-chromium {snapshot['sha']} chromium/third_party/pdfium\n"
    )
    return [notice], f"qt/qtwebengine {tag}, Chromium snapshot {snapshot['sha']}"


def fetch_opengl32sw() -> list[str]:
    """Mesa and LLVM, as `opengl32sw.dll` carries them; see `OPENGL32SW`."""
    notices = []
    for name, version, licence, url, target in OPENGL32SW:
        (OUT / "licenses" / target).write_bytes(_get(url))
        notices.append(
            f"{name}\n"
            + _line("Version", version)
            + _line("Licence", licence)
            + _line("Licence text", [f"licenses/{target}"])
            + f"Recorded in: {url}\n"
        )
    return notices


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
    pdfium, pinned = fetch_pdfium(tag)
    notices += pdfium + fetch_opengl32sw()
    sources.append(pinned)
    header = (
        f"Third-party components of the Qt {tag.removeprefix('v')} libraries this bundle ships\n"
        "(Qt Core, Qt GUI, Qt Widgets, Qt Network, Qt SVG, the Qt Image Formats plugins, Qt PDF\n"
        "and the software OpenGL renderer), as Qt's own qt_attribution.json records list them,\n"
        "and for Qt PDF and the renderer, which no such record covers, from their own sources. Qt itself is under the LGPL; its text is in ../python.txt, under PyQt6-Qt6.\n\n"
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
