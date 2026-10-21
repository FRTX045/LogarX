"""Every control drawn one way, by the application rather than per widget.

Run in a separate process, as `test_text_size` does: the theme installs Fusion,
a palette, a font and a stylesheet on the application, and the shared test
application must keep none of them for the unrelated geometry checks that use
it. One process answers every question below; each test reads its own answer.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

PROBE = r"""
import json, sys
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QMenu, QMenuBar, QTableWidget,
    QTableWidgetItem, QWidget,
)
from PyQt6.QtCore import Qt
from logarc.gui import theme
from logarc.gui.splitter import PanelSplitter
from logarc.style import THEME

qt = QApplication([])
theme.apply_theme(qt)
# What Windows does, after the application font is set as well: menus are
# handed the platform's own menu font, 9 pt under an 11 pt window.
small = QFont(qt.font())
small.setPointSizeF(9.0)
for name in ("QMenuBar", "QMenu"):
    QApplication.setFont(small, name)

def near(image, colour, tolerance=40):
    want = QColor(colour)
    count = 0
    for x in range(image.width()):
        for y in range(image.height()):
            got = image.pixelColor(x, y)
            if (abs(got.red() - want.red()) + abs(got.green() - want.green())
                    + abs(got.blue() - want.blue())) <= tolerance:
                count += 1
    return count

def bluish(image):
    count = 0
    for x in range(image.width()):
        for y in range(image.height()):
            got = image.pixelColor(x, y)
            if got.blue() - got.red() > 60:
                count += 1
    return count

def grab(widget):
    widget.resize(widget.sizeHint())
    return widget.grab().toImage()

facts = {}
ticked = QCheckBox("Wrap long traces"); ticked.setChecked(True)
facts["ticked_accent"] = near(grab(ticked), THEME.accent, 12)
unticked = QCheckBox("Wrap long traces")
facts["unticked_accent"] = near(grab(unticked), THEME.accent, 12)
facts["unticked_outline"] = near(grab(unticked), THEME.muted, 60)

table = QTableWidget(1, 1)
item = QTableWidgetItem("rule"); item.setCheckState(Qt.CheckState.Checked)
table.setItem(0, 0, item); table.resize(160, 60)
facts["item_check_accent"] = near(table.grab().toImage(), THEME.accent, 12)

facts["app_points"] = qt.font().pointSizeF()
bar, menu = QMenuBar(), QMenu()
for polished in (bar, menu):
    polished.ensurePolished()
facts["menubar_points"] = bar.font().pointSizeF()
facts["menu_points"] = menu.font().pointSizeF()

dialog = QDialog()
buttons = QDialogButtonBox(
    QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    | QDialogButtonBox.StandardButton.RestoreDefaults, dialog)
settle = getattr(theme, "settle_buttons", None)
if settle is not None:
    settle(buttons)
facts["restore_auto_default"] = buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults).autoDefault()
facts["cancel_auto_default"] = buttons.button(QDialogButtonBox.StandardButton.Cancel).autoDefault()
facts["ok_default"] = buttons.button(QDialogButtonBox.StandardButton.Ok).isDefault()

make = getattr(theme, "controls_sheet", None)
sheet = make(11.0) if make is not None else ""
default_rule = sheet.split("QPushButton:default", 1)[-1].split("}", 1)[0] if sheet else "missing"
facts["default_rule_bold"] = "font-weight" in default_rule if sheet else None
facts["sheet_sizes_menus"] = "font-size: 11.0pt" in sheet

splitter = PanelSplitter(Qt.Orientation.Horizontal)
splitter.addWidget(QWidget()); splitter.addWidget(QWidget())
splitter.resize(200, 100); splitter.show(); qt.processEvents()
grip = splitter.handle(1)
facts["resting_grip_accent"] = bluish(grip.grab().toImage())

# Last, because it takes the stylesheet away to measure Fusion alone.
from logarc.gui.panels import ClientTable
clients = ClientTable(); clients.resize(420, 500); clients.show(); qt.processEvents()
header = clients._table.horizontalHeader()
shown = [i for i in range(clients._table.columnCount()) if not header.isSectionHidden(i)]
themed = [header.sectionSizeHint(i) for i in shown]
qt.setStyleSheet(""); qt.processEvents()
plain = [header.sectionSizeHint(i) for i in shown]
facts["header_widening"] = max(a - b for a, b in zip(themed, plain))
print(json.dumps(facts))
"""


@pytest.fixture(scope="module")
def facts() -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "QT_SCALE_FACTOR": "1"},
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    answer: dict[str, object] = json.loads(result.stdout.strip().splitlines()[-1])
    return answer


def test_a_ticked_box_is_a_filled_accent_square(facts: dict[str, object]) -> None:
    """It was a bare tick on a box drawn in the ground's own colour."""
    assert int(str(facts["ticked_accent"])) >= 40


def test_an_unticked_box_shows_its_outline_and_no_fill(facts: dict[str, object]) -> None:
    assert int(str(facts["unticked_outline"])) >= 12
    assert facts["unticked_accent"] == 0


def test_a_tick_in_a_table_is_drawn_the_same_way(facts: dict[str, object]) -> None:
    """The rules tab's On column is item-view checks, a different primitive."""
    assert int(str(facts["item_check_accent"])) >= 40


def test_menus_take_the_interface_size_not_the_platforms_menu_font(
    facts: dict[str, object],
) -> None:
    """Windows gives menus its 9 pt menu font; the rest of the window is larger."""
    assert facts["menubar_points"] == facts["app_points"]
    assert facts["menu_points"] == facts["app_points"]
    assert facts["sheet_sizes_menus"] is True


def test_the_default_button_is_not_bold_so_its_label_is_never_clipped(
    facts: dict[str, object],
) -> None:
    """Bold set under `:default` widens the text after the button was sized."""
    assert facts["default_rule_bold"] is False


def test_restore_defaults_and_cancel_are_never_the_default(facts: dict[str, object]) -> None:
    assert facts["restore_auto_default"] is False
    assert facts["cancel_auto_default"] is False
    assert facts["ok_default"] is True


def test_a_resting_splitter_grip_is_quiet(facts: dict[str, object]) -> None:
    """Accent means "chosen" everywhere else; a grip at rest is not chosen."""
    assert facts["resting_grip_accent"] == 0


def test_the_stylesheet_does_not_widen_a_heading(facts: dict[str, object]) -> None:
    """Measured 17 px wider per column than Fusion draws it, which pushed the
    client list's Last column behind a scroll bar at the default window size.
    The client list was fitted to Fusion's headings; the sheet keeps them."""
    assert int(str(facts["header_widening"])) <= 2
