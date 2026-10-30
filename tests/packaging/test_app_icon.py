"""The application's own icon: the file the executable carries and the check that it does.

An icon is the easiest thing for a build to lose without saying so. PyInstaller
accepts a spec with no `icon=` and writes an executable with Windows's default
one, and nothing downstream fails.
"""

from __future__ import annotations

import importlib.util
import re
import struct
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
ICO = ROOT / "packaging" / "icon" / "zodiarc.ico"
PNG = ROOT / "src" / "zodiarc" / "gui" / "zodiarc.png"
SPEC = ROOT / "packaging" / "zodiarc.spec"

#: What Windows asks of an executable's icon: the sizes the shell, the taskbar and
#: the title bar each pick from, up to the 256 px of the large views.
SIZES = (16, 24, 32, 48, 64, 128, 256)


def _entries(data: bytes) -> list[tuple[int, int, bytes]]:
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert (reserved, kind) == (0, 1), "not an .ico file"
    found = []
    for index in range(count):
        width, height, _, _, _, _, size, offset = struct.unpack_from(
            "<BBBBHHII", data, 6 + 16 * index
        )
        found.append((width or 256, height or 256, data[offset : offset + size]))
    return found


def test_the_icon_file_holds_every_size_windows_picks_from() -> None:
    entries = _entries(ICO.read_bytes())

    assert sorted(width for width, _, _ in entries) == list(SIZES)
    assert all(width == height for width, height, _ in entries)
    assert all(image.startswith(b"\x89PNG") for _, _, image in entries)


def test_the_icon_is_a_white_mark_on_a_dark_tile_with_rounded_corners() -> None:
    pytest.importorskip("PyQt6")
    from PyQt6.QtGui import QColor, QImage

    image = QImage(str(PNG)).convertToFormat(QImage.Format.Format_ARGB32)
    assert image.width() == image.height() == 256

    assert QColor.fromRgba(image.pixel(0, 0)).alpha() == 0, "the corner is rounded off"
    tile = QColor.fromRgba(image.pixel(128, 8))
    assert tile.alpha() == 255 and tile.lightness() < 60, "the tile behind the mark is dark"
    brightest = max(
        QColor.fromRgba(image.pixel(x, y)).lightness()
        for x in range(64, 192)
        for y in range(64, 192)
    )
    assert brightest > 240, "the mark is white"


def test_the_spec_gives_the_executable_this_icon() -> None:
    spec = SPEC.read_text(encoding="utf-8")

    match = re.search(r"\bicon=(.+?),\n", spec)
    assert match is not None, "EXE(...) has no icon="
    assert "icon" in match.group(1) and "zodiarc.ico" in match.group(1)
    assert ICO.is_file()


def test_the_spec_ships_the_picture_the_window_draws_in_its_title_bar() -> None:
    spec = SPEC.read_text(encoding="utf-8")

    assert '"zodiarc.png"' in spec and "zodiarc/gui" in spec


def _rebuild() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "rebuild_for_icon", ROOT / "packaging" / "rebuild.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _bundle(root: Path, *, exe: bytes | Path | None, png: bool = True) -> Path:
    bundle = root / "zodiarc"
    (bundle / "_internal" / "zodiarc" / "gui").mkdir(parents=True)
    if png:
        (bundle / "_internal" / "zodiarc" / "gui" / "zodiarc.png").write_bytes(PNG.read_bytes())
    if isinstance(exe, Path):
        (bundle / "zodiarc.exe").write_bytes(exe.read_bytes())
    elif exe is not None:
        (bundle / "zodiarc.exe").write_bytes(exe)
    return bundle


def test_a_bundle_whose_executable_cannot_be_read_is_refused(tmp_path: Path) -> None:
    problem = _rebuild().check_app_icon(_bundle(tmp_path, exe=b"not an executable"))

    assert problem is not None and "zodiarc.exe" in problem


def test_a_bundle_without_the_window_picture_is_refused(tmp_path: Path) -> None:
    problem = _rebuild().check_app_icon(_bundle(tmp_path, exe=None, png=False))

    assert problem is not None and "zodiarc.png" in problem


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows executable carries the icon")
def test_an_executable_with_no_icon_resource_is_refused(tmp_path: Path) -> None:
    """A PE file with resources but no icon group: Windows's own `ping.exe` has
    version information and none."""
    ping = Path(r"C:\Windows\System32\ping.exe")
    if not ping.exists():
        pytest.skip("no ping.exe here")

    problem = _rebuild().check_app_icon(_bundle(tmp_path, exe=ping))

    assert problem is not None and "icon" in problem


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows executable carries the icon")
def test_an_executable_that_carries_an_icon_passes(tmp_path: Path) -> None:
    """Python's own executable is the stand-in: it carries its icon group."""
    base = Path(getattr(sys, "_base_executable", sys.executable))

    assert _rebuild().check_app_icon(_bundle(tmp_path, exe=base)) is None
