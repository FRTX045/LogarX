"""Make the application's icon from the supplied mark.

    python packaging/icon/make_icon.py

Writes `packaging/icon/zodiarc.ico`, which the executable carries, and
`src/zodiarc/gui/zodiarc.png`, which the window draws in its title bar and the
taskbar. Both are committed: this only needs running when the mark changes.

`zodiarc-mark.png` is the mark as supplied, white on transparent. White vanishes
on a light taskbar, so the icon sets it on a dark tile with rounded corners, the
same near-black as the project banner.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt
from PyQt6.QtGui import QColor, QGuiApplication, QImage, QPainter

HERE = Path(__file__).resolve().parent
MARK = HERE / "zodiarc-mark.png"
ICO = HERE / "zodiarc.ico"
PNG = HERE.parents[1] / "src" / "zodiarc" / "gui" / "zodiarc.png"

#: The sizes Windows picks from, up to the 256 px of its large views.
SIZES = (16, 24, 32, 48, 64, 128, 256)
TILE = QColor(10, 10, 18)
#: How much of the tile's width the mark takes, and how round its corners are.
SHARE = 0.66
CORNER = 0.22


def _trimmed(image: QImage) -> QImage:
    """The mark without the empty margin the supplied picture carries."""
    left, top, right, bottom = image.width(), image.height(), -1, -1
    for y in range(image.height()):
        for x in range(image.width()):
            if QColor.fromRgba(image.pixel(x, y)).alpha() > 8:
                left, right = min(left, x), max(right, x)
                top, bottom = min(top, y), max(bottom, y)
    return image.copy(left, top, right - left + 1, bottom - top + 1)


def render(size: int, mark: QImage) -> QImage:
    out = QImage(size, size, QImage.Format.Format_ARGB32)
    out.fill(Qt.GlobalColor.transparent)
    painter = QPainter(out)
    painter.setRenderHints(
        QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform
    )
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(TILE)
    radius = size * CORNER
    painter.drawRoundedRect(QRectF(0, 0, size, size), radius, radius)
    width = size * SHARE
    height = width * mark.height() / mark.width()
    painter.drawImage(QRectF((size - width) / 2, (size - height) / 2, width, height), mark)
    painter.end()
    return out


def _png(image: QImage) -> bytes:
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(data)


def _ico(images: list[tuple[int, bytes]]) -> bytes:
    """An .ico of PNG frames, which Windows has read since Vista."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    directory, body = b"", b""
    for size, png in images:
        directory += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset)
        body += png
        offset += len(png)
    return header + directory + body


def main() -> int:
    _ = QGuiApplication(sys.argv)
    mark = _trimmed(QImage(str(MARK)).convertToFormat(QImage.Format.Format_ARGB32))
    frames = [(size, _png(render(size, mark))) for size in SIZES]
    ICO.write_bytes(_ico(frames))
    PNG.write_bytes(dict(frames)[256])
    print(f"wrote {ICO} ({ICO.stat().st_size} bytes) and {PNG} ({PNG.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
