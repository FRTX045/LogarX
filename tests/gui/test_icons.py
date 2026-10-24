"""Drawing an icon, taking a reader's own image, and keeping their choices."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QColor, QImage
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Severity
from logarc.gui._qt import required
from logarc.gui.icon_set import file_name_of, icons_dir
from logarc.gui.icons import (
    DARK_INK,
    ICON_PIXELS,
    LIGHT_INK,
    MAX_FILE_BYTES,
    adopt,
    adopt_icon_file,
    first_drawable,
    icon_file_problem,
    icon_pixmap,
    ink_for,
    read_kind_icons,
    write_kind_icons,
)
from logarc.style import THEME

#: A small drawing in a colour of its own: an icon of the reader's.
SQUARE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">'
    '<rect x="1" y="1" width="8" height="8" fill="#00ff00"/></svg>'
)


def contrast(a: str, b: str) -> float:
    """WCAG's contrast ratio, written out here rather than taken from the code under test."""

    def luminance(colour: str) -> float:
        channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def opaque_pixels(image: QImage) -> Iterator[tuple[int, int]]:
    for y in range(image.height()):
        for x in range(image.width()):
            if QColor.fromRgba(image.pixel(x, y)).alpha() > 0:
                yield x, y


def _file(directory: Path, name: str, text: str = SQUARE) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def test_ink_matches_the_approved_mockup(qt_app: QApplication) -> None:
    """White on the grey, orange and red circles, near-black on teal and amber:
    the look the reader approved in the first mockup."""
    picks = {severity: ink_for(THEME.severity[severity]) for severity in Severity}
    assert picks == {
        Severity.INFO: LIGHT_INK,
        Severity.LOW: DARK_INK,
        Severity.MEDIUM: DARK_INK,
        Severity.HIGH: LIGHT_INK,
        Severity.CRITICAL: LIGHT_INK,
    }
    assert (LIGHT_INK, DARK_INK) == ("#ffffff", "#16181c")


def test_every_ink_clears_three_to_one(qt_app: QApplication) -> None:
    for fill in THEME.severity.values():
        assert contrast(ink_for(fill), fill) >= 3.0, fill


def test_a_lucide_icon_draws_in_the_colour_asked(qt_app: QApplication) -> None:
    image = required(icon_pixmap("syringe", "#ff0000")).toImage()
    assert image.width() == image.height() == ICON_PIXELS
    inked = [QColor.fromRgba(image.pixel(x, y)) for x, y in opaque_pixels(image)]
    assert inked, "something was drawn"
    assert all(colour.red() > colour.green() and colour.red() > colour.blue() for colour in inked)


def test_an_unknown_name_draws_nothing(qt_app: QApplication) -> None:
    assert icon_pixmap("skul", "#ffffff") is None
    assert icon_pixmap("file:gone.svg", "#ffffff") is None
    assert icon_pixmap("file:../escape.svg", "#ffffff") is None


def test_a_readers_svg_keeps_its_own_colours(qt_app: QApplication) -> None:
    _file(icons_dir(), "square.svg")
    image = required(icon_pixmap("file:square.svg", "#ff0000")).toImage()
    centre = QColor.fromRgba(image.pixel(ICON_PIXELS // 2, ICON_PIXELS // 2))
    assert (centre.red(), centre.green()) == (0, 255)


def test_a_readers_png_draws(qt_app: QApplication) -> None:
    image = QImage(40, 20, QImage.Format.Format_ARGB32)
    image.fill(QColor("#0000ff"))
    icons_dir().mkdir(parents=True)
    image.save(str(icons_dir() / "wide.png"))
    drawn = required(icon_pixmap("file:wide.png", "#ffffff")).toImage()
    middle = QColor.fromRgba(drawn.pixel(ICON_PIXELS // 2, ICON_PIXELS // 2))
    top = QColor.fromRgba(drawn.pixel(ICON_PIXELS // 2, 2))
    assert middle.blue() == 255
    assert top.alpha() == 0, "kept its shape: twice as wide as tall, centred"


def test_a_blank_svg_is_refused(qt_app: QApplication, tmp_path: Path) -> None:
    """It parses, and draws nothing. Accepted, the reader would see an empty circle."""
    blank = _file(tmp_path, "blank.svg", '<svg xmlns="http://www.w3.org/2000/svg"/>')
    assert icon_file_problem(blank) == "blank.svg could not be drawn."


def test_a_file_that_is_not_an_image_is_refused(qt_app: QApplication, tmp_path: Path) -> None:
    broken = _file(tmp_path, "broken.svg", "this is not svg")
    assert icon_file_problem(broken) == "broken.svg could not be drawn."


def test_oversized_and_wrong_type_files_are_refused(qt_app: QApplication, tmp_path: Path) -> None:
    big = tmp_path / "big.svg"
    big.write_text(SQUARE + " " * (MAX_FILE_BYTES + 1 - len(SQUARE)), encoding="utf-8")
    assert big.stat().st_size == MAX_FILE_BYTES + 1 == 1_048_577
    assert icon_file_problem(big) == "big.svg is over 1 MB. Pick a smaller image."
    gif = _file(tmp_path, "logo.gif")
    assert icon_file_problem(gif) == "logo.gif is not an SVG or PNG file."


def test_a_good_file_has_no_problem(qt_app: QApplication, tmp_path: Path) -> None:
    assert icon_file_problem(_file(tmp_path, "Logo.SVG")) == ""


def test_a_deleted_file_falls_back_to_the_next_candidate(
    qt_app: QApplication, tmp_path: Path
) -> None:
    value = adopt_icon_file(_file(tmp_path, "logo.svg"))
    (icons_dir() / required(file_name_of(value), "name")).unlink()
    drawn = first_drawable([value, "syringe"], "#ffffff")
    assert drawn.toImage() == required(icon_pixmap("syringe", "#ffffff")).toImage()


def test_nothing_drawable_gives_an_empty_pixmap(qt_app: QApplication) -> None:
    assert first_drawable(["skul", "file:gone.svg"], "#ffffff").isNull()


def test_adopting_reuses_an_identical_file_and_never_overwrites(
    qt_app: QApplication, tmp_path: Path
) -> None:
    first = _file(tmp_path / "a", "logo.svg")
    same = _file(tmp_path / "b", "logo.svg")
    different = _file(tmp_path / "c", "logo.svg", SQUARE.replace("#00ff00", "#0000ff"))
    another = _file(tmp_path / "d", "logo.svg", SQUARE.replace("#00ff00", "#ff00ff"))

    assert adopt_icon_file(first) == "file:logo.svg"
    assert adopt_icon_file(same) == "file:logo.svg"
    assert adopt_icon_file(different) == "file:logo-2.svg"
    assert adopt_icon_file(another) == "file:logo-3.svg"
    assert adopt_icon_file(different) == "file:logo-2.svg"
    assert (icons_dir() / "logo.svg").read_bytes() == first.read_bytes()
    assert sorted(path.name for path in icons_dir().iterdir()) == [
        "logo-2.svg",
        "logo-3.svg",
        "logo.svg",
    ]


def test_an_adopted_name_with_dots_in_a_row_is_still_usable(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """`..` is refused in a `file:` value as a way out of the folder, so a copy
    kept under its own name `my..logo.svg` would be a choice nothing can draw."""
    value = adopt_icon_file(_file(tmp_path, "my..logo.svg"))
    assert value == "file:my.logo.svg"
    assert icon_pixmap(value, "#ffffff") is not None


def test_adopt_copies_only_a_file(qt_app: QApplication, tmp_path: Path) -> None:
    assert adopt("skull") == "skull"
    assert adopt(None) is None
    assert adopt(_file(tmp_path, "mine.png")) == "file:mine.png"


def test_drawing_the_same_icon_twice_renders_once(qt_app: QApplication) -> None:
    first = required(icon_pixmap("zap", "#ffffff"))
    assert required(icon_pixmap("zap", "#ffffff")).cacheKey() == first.cacheKey()
    assert required(icon_pixmap("zap", "#000000")).cacheKey() != first.cacheKey()


def test_a_replaced_file_is_drawn_again(qt_app: QApplication) -> None:
    import os

    path = _file(icons_dir(), "mine.svg")
    green = required(icon_pixmap("file:mine.svg", "#ffffff")).toImage()
    path.write_text(SQUARE.replace("#00ff00", "#0000ff"), encoding="utf-8")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))
    blue = required(icon_pixmap("file:mine.svg", "#ffffff")).toImage()
    assert green != blue


def test_kind_icons_round_trip_and_ignore_strangers(qt_app: QApplication, tmp_path: Path) -> None:
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    settings.setValue("icons/not_a_kind", "zap")
    settings.setValue("icons/browsing", "")
    write_kind_icons(
        settings,
        {ActivityCategory.INJECTION: "skull", ActivityCategory.SSRF: "server"},
    )
    assert read_kind_icons(settings.value) == {ActivityCategory.INJECTION: "skull"}
    assert settings.value("icons/ssrf") is None, "SSRF's default is not written down"

    write_kind_icons(settings, {})
    assert settings.value("icons/injection") is None, "going back to default forgets it"


@pytest.mark.parametrize("stored", [3, ["zap"], None])
def test_a_stored_value_that_is_not_text_is_ignored(stored: object) -> None:
    assert read_kind_icons({"icons/injection": stored}.get) == {}
