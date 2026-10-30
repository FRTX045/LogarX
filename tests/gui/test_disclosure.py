"""Optional text stays available through mouse, keyboard and fullscreen use."""

from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QLabel

from zodiarc.gui.app import MainWindow
from zodiarc.gui.disclosure import Disclosure


def test_explanations_start_closed_and_open_with_mouse_or_keyboard(qt_app):
    content = QLabel("Supporting details")
    section = Disclosure("About this view", content)
    section.show()
    qt_app.processEvents()
    assert content.isHidden()
    QTest.mouseClick(section.button, Qt.MouseButton.LeftButton)
    assert content.isVisible()
    assert section.button.arrowType() == Qt.ArrowType.DownArrow
    content.setText("Updated supporting details")
    QTest.keyClick(section.button, Qt.Key.Key_Space)
    assert content.isHidden()
    QTest.keyClick(section.button, Qt.Key.Key_Space)
    assert content.isVisible()
    assert content.text() == "Updated supporting details"
    section.close()


def test_graph_key_choice_survives_fullscreen(qt_app):
    window = MainWindow()
    window.show()
    qt_app.processEvents()
    assert window._legend.isHidden()
    for opened in (True, False):
        window._graph_key.button.setChecked(opened)
        qt_app.processEvents()
        window._full_screen.apply(True)
        qt_app.processEvents()
        assert not window._graph_key.isVisible()
        assert not window._legend.isVisible()
        window._full_screen.apply(False)
        qt_app.processEvents()
        assert window._graph_key.isVisible()
        assert window._legend.isVisible() == opened
    window.close()
