"""Draw an icon, take in a reader's own image, and keep the icons they chose.

An icon is named by a *value*: a Lucide name such as `syringe`, or `file:` and
the name of an image in the reader's icons folder (`icon_set`). Everything that
draws one asks `icon_pixmap` or `first_drawable` here, so a missing file, a
name nobody knows and an image that draws nothing are all answered the same way
in every place: by the next icon in line, never by an error.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final, TypeAlias

from PyQt6.QtCore import QByteArray, QRectF, QSettings, QSizeF, Qt
from PyQt6.QtGui import QColor, QImage, QImageReader, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

from logarc.core.activity import ActivityCategory
from logarc.gui.icon_set import DEFAULT_ICONS, FILE_PREFIX, file_name_of, icons_dir, lucide

__all__ = [
    "DARK_INK",
    "ICON_KEY_PREFIX",
    "ICON_PIXELS",
    "LIGHT_INK",
    "MAX_FILE_BYTES",
    "Picked",
    "adopt",
    "adopt_icon_file",
    "first_drawable",
    "icon_file_problem",
    "icon_pixmap",
    "ink_for",
    "read_kind_icons",
    "write_kind_icons",
]

#: Drawn once at this size and scaled by whoever shows it. Large enough to stay
#: sharp inside the biggest circle at the zoom a reader reads detail at.
ICON_PIXELS: Final = 192

LIGHT_INK: Final = "#ffffff"
DARK_INK: Final = "#16181c"

#: What a symbol needs against what it is drawn on (WCAG 1.4.11).
_SYMBOL_CONTRAST: Final = 3.0

#: An icon is drawn many times over on a graph; an image larger than this is
#: almost certainly not one.
MAX_FILE_BYTES: Final = 1_048_576

_KINDS_OF_FILE: Final = (".svg", ".png")

ICON_KEY_PREFIX: Final = "icons/"

#: What a picker hands back: a value, a file of the reader's not yet copied in,
#: or None for "the default".
Picked: TypeAlias = "str | Path | None"

_drawn: dict[tuple[str, str, int, int], QPixmap | None] = {}


def _luminance(colour: str) -> float:
    found = QColor(colour)
    linear = [
        c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        for c in (found.redF(), found.greenF(), found.blueF())
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def ink_for(fill: str) -> str:
    """The colour an icon is drawn in on `fill`.

    White wherever white is legible, which on today's theme is the grey, orange
    and red circles: the look the reader chose from the mockups. Near-black
    elsewhere. Worked out from the fill, so a change of theme cannot leave an
    icon unreadable.
    """
    contrast = 1.05 / (_luminance(fill) + 0.05)
    return LIGHT_INK if contrast >= _SYMBOL_CONTRAST else DARK_INK


def _anything_drawn(pixmap: QPixmap) -> bool:
    image = pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
    bits = image.constBits()
    if bits is None:  # pragma: no cover - a non-null image always has bits
        return False
    # Alpha is the fourth byte of each little-endian ARGB32 pixel.
    return any(bits.asstring(image.sizeInBytes())[3::4])


def _canvas(size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    return pixmap


def _fitted(width: float, height: float, size: int) -> QRectF:
    """A box of `width` by `height`'s shape, as large as fits in `size` square, centred."""
    if width <= 0 or height <= 0:
        width = height = 1.0
    scale = size / max(width, height)
    shown = QSizeF(width * scale, height * scale)
    return QRectF(
        (size - shown.width()) / 2, (size - shown.height()) / 2, shown.width(), shown.height()
    )


def _from_svg(renderer: QSvgRenderer, size: int) -> QPixmap | None:
    if not renderer.isValid():
        return None
    box = renderer.viewBoxF()
    pixmap = _canvas(size)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, _fitted(box.width(), box.height(), size))
    painter.end()
    return pixmap if _anything_drawn(pixmap) else None


def _from_png(path: Path, size: int) -> QPixmap | None:
    # Through `QImageReader`, whose allocation limit refuses an image that
    # would decode to hundreds of megabytes from a small file.
    image = QImageReader(str(path)).read()
    if image.isNull():
        return None
    pixmap = _canvas(size)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    painter.drawImage(_fitted(image.width(), image.height(), size), image)
    painter.end()
    return pixmap if _anything_drawn(pixmap) else None


def _from_file(path: Path, size: int) -> QPixmap | None:
    suffix = path.suffix.lower()
    if suffix == ".svg":
        return _from_svg(QSvgRenderer(str(path)), size)
    if suffix == ".png":
        return _from_png(path, size)
    return None


def icon_pixmap(value: str, colour: str, size: int = ICON_PIXELS) -> QPixmap | None:
    """`value` drawn `size` pixels square on a transparent ground, or None.

    A Lucide icon is drawn in `colour`; an image of the reader's keeps its own.
    None for a name nobody knows, a file that is gone, and anything that draws
    nothing at all. Kept once drawn, by the file's modification time too, so an
    image replaced under the same name is drawn again.
    """
    icon = lucide().get(value)
    path: Path | None = None
    stamp = 0
    if icon is None:
        name = file_name_of(value)
        if name is None:
            return None
        path = icons_dir() / name
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            return None
    key = (value, colour, size, stamp)
    if key not in _drawn:
        if icon is not None:
            svg = icon.svg.replace("currentColor", colour)
            _drawn[key] = _from_svg(QSvgRenderer(QByteArray(svg.encode())), size)
        elif path is not None:  # pragma: no branch - set whenever icon is None
            _drawn[key] = _from_file(path, size)
    return _drawn[key]


def first_drawable(candidates: Sequence[str], colour: str, size: int = ICON_PIXELS) -> QPixmap:
    """The first of `candidates` that draws; an empty pixmap only if none does."""
    for value in candidates:
        if (pixmap := icon_pixmap(value, colour, size)) is not None:
            return pixmap
    return QPixmap()


def icon_file_problem(path: Path) -> str:
    """Why `path` cannot be a reader's icon, in one sentence; empty when it can."""
    name = path.name
    if path.suffix.lower() not in _KINDS_OF_FILE:
        return f"{name} is not an SVG or PNG file."
    try:
        too_big = path.stat().st_size > MAX_FILE_BYTES
    except OSError:
        return f"{name} could not be drawn."
    if too_big:
        return f"{name} is over 1 MB. Pick a smaller image."
    if _from_file(path, ICON_PIXELS) is None:
        return f"{name} could not be drawn."
    return ""


def adopt_icon_file(path: Path) -> str:
    """Copy `path` into the reader's icons folder and return the value naming it.

    Copied so the choice survives the original being moved or deleted. A file
    of the same name and the same bytes already there is the same image, and is
    used as it is; one with different bytes is never overwritten, the copy is
    numbered instead.
    """
    folder = icons_dir()
    folder.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()
    # Dots in a row would read as a way out of the folder (`file_name_of`).
    own = Path(re.sub(r"\.{2,}", ".", path.name))
    candidate, number = own.name, 2
    while (folder / candidate).exists():
        if (folder / candidate).read_bytes() == data:
            return FILE_PREFIX + candidate
        candidate, number = f"{own.stem}-{number}{own.suffix}", number + 1
    (folder / candidate).write_bytes(data)
    return FILE_PREFIX + candidate


def adopt(picked: Picked) -> str | None:
    """A picker's answer as a value to keep: a file of the reader's is copied in first."""
    return adopt_icon_file(picked) if isinstance(picked, Path) else picked


def read_kind_icons(stored: Callable[[str], object]) -> dict[ActivityCategory, str]:
    """The icons the reader chose for kinds, given `QSettings.value` or its like.

    Anything that is not a non-empty piece of text is passed over: settings
    outlive the code that wrote them.
    """
    chosen: dict[ActivityCategory, str] = {}
    for kind in ActivityCategory:
        raw = stored(ICON_KEY_PREFIX + kind.value)
        if isinstance(raw, str) and raw:
            chosen[kind] = raw
    return chosen


def write_kind_icons(settings: QSettings, kinds: Mapping[ActivityCategory, str]) -> None:
    """Keep `kinds`: one entry per kind whose icon is not its default, none for the rest."""
    for kind in ActivityCategory:
        key = ICON_KEY_PREFIX + kind.value
        value = kinds.get(kind)
        if value and value != DEFAULT_ICONS[kind]:
            settings.setValue(key, value)
        else:
            settings.remove(key)
