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
    path_pixmap,
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


def test_changing_a_drawn_pixmap_does_not_change_the_next_one(qt_app: QApplication) -> None:
    """Every caller is handed the cache's pixmap. The legend and the picker set
    a device pixel ratio on theirs, and on a 125% screen the legend's 20 px kind
    icons share a key with the Preferences grid and Add rule's chip: changed in
    place, the cached icon came out shrunk wherever it was drawn next."""
    first = required(icon_pixmap("zap", "#ffffff", 20))
    first.setDevicePixelRatio(1.25)
    again = required(icon_pixmap("zap", "#ffffff", 20))
    assert again.devicePixelRatio() == 1.0
    assert first_drawable(["zap"], "#ffffff", 20).devicePixelRatio() == 1.0


def _svg_with(body: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'
        ' viewBox="0 0 10 10"><rect x="1" y="1" width="8" height="8" fill="#00ff00"/>'
        f"{body}</svg>"
    )


@pytest.mark.parametrize(
    "body",
    [
        '<image href="data:image/png;base64,AAAAAAAA" width="8" height="8"/>',
        '<image xlink:href="gone.png" width="8" height="8"/>',
        '<image href="" width="8" height="8"/>',
        '<image href="data:image/png;base64,iVBORw0KGgo=" width="0" height="8"/>',
    ],
)
def test_an_svg_with_an_image_qt_cannot_draw_is_refused_with_the_reason(
    qt_app: QApplication, tmp_path: Path, body: str
) -> None:
    """The rest of the icon would draw and that image would vanish from it
    without a word: a PDF in the packaged application, which leaves Qt PDF
    out, or anything else Qt cannot read. Qt decides, as it does when drawing,
    so no reading of the file here can disagree with it."""
    path = _file(tmp_path, "broken-image.svg", _svg_with(body))

    assert icon_file_problem(path) == (
        "broken-image.svg contains an image logarc cannot draw. Save it as SVG or PNG first."
    )


@pytest.mark.parametrize(
    "body",
    [
        '<!-- traced from href="original.pdf" -->',
        '<a href="manual.pdf"><rect x="2" y="2" width="2" height="2" fill="#000"/></a>',
        '<image href="data:image/png;base64,'
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="'
        ' width="1" height="1"/>',
    ],
)
def test_an_svg_that_only_mentions_another_file_is_accepted(
    qt_app: QApplication, tmp_path: Path, body: str
) -> None:
    """A comment or a link is not an embedded image, and an image Qt reads
    draws with the rest."""
    assert icon_file_problem(_file(tmp_path, "fine.svg", _svg_with(body))) == ""


def test_an_image_qt_cannot_draw_is_refused_even_with_qt_s_warnings_silenced(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """Qt reports a dropped image through its logging, which logging rules can
    silence. Then nothing can be confirmed, so an icon holding an image is
    refused rather than trusted."""
    from PyQt6.QtCore import QLoggingCategory

    body = '<image xlink:href="gone.png" width="8" height="8"/>'
    path = _file(tmp_path, "quiet.svg", _svg_with(body))
    QLoggingCategory.setFilterRules("qt.svg.warning=false")
    try:
        problem = icon_file_problem(path)
        plain = icon_file_problem(_file(tmp_path, "plain.svg", _svg_with("")))
    finally:
        QLoggingCategory.setFilterRules("")

    assert "contains an image logarc cannot draw" in problem
    assert plain == "", "an icon with no image needs nothing confirmed"


def test_an_svg_named_png_is_not_drawn_as_one(qt_app: QApplication, tmp_path: Path) -> None:
    """Read as what its name says. Read by content, an SVG named `.png` would
    be drawn without the checks an SVG gets."""
    renamed = _file(tmp_path, "renamed.png", _svg_with(""))

    assert icon_file_problem(renamed) == "renamed.png could not be drawn."


def test_a_saved_icon_with_an_image_qt_cannot_draw_falls_back(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """One copied in before the check existed, or by hand, is drawn by the same
    rule: not at all, so the next candidate is used, rather than with a hole."""
    value = adopt_icon_file(_file(tmp_path, "logo.svg"))
    saved = icons_dir() / required(file_name_of(value), "name")
    saved.write_text(_svg_with('<image xlink:href="gone.png" width="8" height="8"/>'), "utf-8")

    assert icon_pixmap(value, "#000000") is None


def test_a_utf16_icon_with_an_image_is_refused_with_qt_s_warnings_silenced(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """Qt reads the encoding the file declares, so the check for an image when
    nothing can be confirmed has to find one in UTF-16 too."""
    from PyQt6.QtCore import QLoggingCategory

    path = tmp_path / "wide.svg"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-16"?>'
        + _svg_with('<image xlink:href="gone.png" width="8" height="8"/>'),
        encoding="utf-16",
    )
    QLoggingCategory.setFilterRules("qt.svg.warning=false")
    try:
        problem = icon_file_problem(path)
        drawn = path_pixmap(path)
    finally:
        QLoggingCategory.setFilterRules("")

    assert "contains an image logarc cannot draw" in problem
    assert drawn is None


_UNRESOLVED = '<use href="#nothing"/>'


def test_qt_s_other_messages_still_reach_the_handler_before_this_one(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """Asked of the check alone: the drawing after it reports the same message
    through whatever handler is in place, which would hide a check that ate it."""
    from PyQt6.QtCore import qInstallMessageHandler

    from logarc.gui.icons import _unreadable_images

    seen: list[str] = []
    previous = qInstallMessageHandler(lambda kind, context, message: seen.append(message))
    try:
        _unreadable_images(_file(tmp_path, "use.svg", _svg_with(_UNRESOLVED)))
    finally:
        qInstallMessageHandler(previous)

    assert any("#nothing" in message for message in seen)


def test_qt_s_other_messages_go_to_stderr_when_no_handler_was_set(
    qt_app: QApplication, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Where Qt's own handler would have put them, rather than nowhere."""
    from PyQt6.QtCore import qInstallMessageHandler

    previous = qInstallMessageHandler(None)
    try:
        icon_file_problem(_file(tmp_path, "use.svg", _svg_with(_UNRESOLVED)))
    finally:
        qInstallMessageHandler(previous)

    assert "#nothing" in capsys.readouterr().err


def test_an_image_made_by_an_entity_is_refused_with_qt_s_warnings_silenced(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """An entity can expand to an `<image>` with no such text in the file, so
    when nothing can be confirmed an SVG that declares one is not trusted."""
    from PyQt6.QtCore import QLoggingCategory

    svg = (
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY picture '
        "\"&#60;image href='gone.png' width='8' height='8'/>\">]>" + _svg_with("&picture;")
    )
    path = _file(tmp_path, "entity.svg", svg)
    QLoggingCategory.setFilterRules("qt.svg.warning=false")
    try:
        problem = icon_file_problem(path)
        drawn = path_pixmap(path)
    finally:
        QLoggingCategory.setFilterRules("")

    assert "contains an image logarc cannot draw" in problem
    assert drawn is None


def test_an_image_under_any_namespace_prefix_is_refused_with_qt_s_warnings_silenced(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """Qt reads the element by its local name, whatever prefix it is bound to."""
    from PyQt6.QtCore import QLoggingCategory

    svg = _svg_with(
        '<é:image xmlns:é="http://www.w3.org/2000/svg" href="gone.png" width="8" height="8"/>'
    )
    path = _file(tmp_path, "prefixed.svg", svg)
    QLoggingCategory.setFilterRules("qt.svg.warning=false")
    try:
        problem = icon_file_problem(path)
    finally:
        QLoggingCategory.setFilterRules("")

    assert "contains an image logarc cannot draw" in problem
