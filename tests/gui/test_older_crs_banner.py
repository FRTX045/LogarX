"""The window telling a reader that a case was checked with an older CRS.

The wording is tested next door, without a display. This is the other half: the
strip goes up on a case whose CRS results were made by an older CRS, offers to
run CRS again, and stays down on a case checked by the CRS here or never
checked at all. Until 2026-10-14 the Windows sidecar missed every file-path
attack, and a case checked then shows those results until CRS runs again.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QPushButton

from conftest import settled
from logarx.case import Case
from logarx.detect.crs import SidecarConfig
from logarx.detect.crs.store import write_detections
from logarx.enrich import crs_config
from logarx.gui import app as app_module
from logarx.gui.app import MainWindow

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"',
]


@pytest.fixture
def crs_here(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SidecarConfig:
    """The CRS this computer would run, without needing the sidecar built."""
    base = SidecarConfig(rules=tmp_path, conf=tmp_path)
    monkeypatch.setattr(app_module, "_crs_config_now", lambda hosts: crs_config(hosts, base))
    return crs_config((), base)


def _case(tmp_path: Path, made_with: dict[str, object] | None) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    root = tmp_path / "case"
    with Case.create(root) as case:
        case.ingest([log])
        if made_with is not None:
            write_detections(case.root, [])
            case.manifest.config.update(made_with)
            case.manifest.save(case.root)
    return root


def _opened(qt_app: QApplication, root: Path) -> MainWindow:
    window = MainWindow()
    window.show()
    window._load_case(root)
    settled(qt_app)
    return window


def _run_again(window: MainWindow) -> QPushButton:
    (button,) = [
        button
        for button in window._older_crs.findChildren(QPushButton)
        if button.text() == "Run CRS again"
    ]
    return button


def test_a_case_checked_by_an_older_crs_puts_the_strip_up(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    older = {**crs_here.as_config(), "crs_fingerprint": "0123456789abcdef"}

    window = _opened(qt_app, _case(tmp_path, older))

    assert window._older_crs.isVisible()
    assert "older" in window._older_crs.text()
    assert _run_again(window).isVisible()


def test_the_button_runs_crs_on_the_case(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    older = {**crs_here.as_config(), "crs_fingerprint": "0123456789abcdef"}
    window = _opened(qt_app, _case(tmp_path, older))
    asked: list[bool] = []
    window._run_crs_now = lambda: asked.append(True)  # type: ignore[method-assign]

    _run_again(window).click()

    assert asked == [True]


def test_a_case_checked_by_the_crs_here_leaves_the_strip_down(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    window = _opened(qt_app, _case(tmp_path, crs_here.as_config()))

    assert not window._older_crs.isVisible()


def test_a_case_never_checked_with_crs_leaves_the_strip_down(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    window = _opened(qt_app, _case(tmp_path, None))

    assert not window._older_crs.isVisible()


def test_opening_a_current_case_after_an_older_one_takes_the_strip_down(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    older = {**crs_here.as_config(), "crs_fingerprint": "0123456789abcdef"}
    window = _opened(qt_app, _case(tmp_path / "old", older))
    assert window._older_crs.isVisible(), "premise: the first case is older"

    window._load_case(_case(tmp_path / "new", crs_here.as_config()))
    settled(qt_app)

    assert not window._older_crs.isVisible()


def test_without_crs_here_the_strip_stays_down(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_crs_config_now", lambda hosts: None)
    older = {**SidecarConfig().as_config(), "crs_fingerprint": "0123456789abcdef"}

    window = _opened(qt_app, _case(tmp_path, older))

    assert not window._older_crs.isVisible()


def test_a_case_checked_for_its_own_site_by_the_crs_here_leaves_the_strip_down(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CRS was told the case's own site name, so the comparison has to be told
    it too; against `localhost` every such case would look out of date."""
    base = SidecarConfig(rules=tmp_path, conf=tmp_path)
    monkeypatch.setattr(app_module, "_crs_config_now", lambda hosts: crs_config(hosts, base))
    root = _case(tmp_path, crs_config(("shop.test",), base).as_config())
    with Case.open(root) as case:
        case.set_site_hosts(["shop.test"])

    window = _opened(qt_app, root)

    assert not window._older_crs.isVisible()


def test_a_case_whose_crs_results_were_deleted_leaves_the_strip_down(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    """The manifest still names a configuration, but there are no CRS results
    left to be out of date: the case reads as never checked."""
    older = {**crs_here.as_config(), "crs_fingerprint": "0123456789abcdef"}
    root = _case(tmp_path, older)
    (root / "crs.jsonl").unlink()

    window = _opened(qt_app, root)

    assert not window._older_crs.isVisible()


def test_crs_that_cannot_run_here_offers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(self: SidecarConfig) -> None:
        raise app_module.CrsUnavailableError("no sidecar")

    monkeypatch.setattr(SidecarConfig, "check", missing)

    assert app_module._crs_config_now(("shop.test",)) is None


def test_crs_that_can_run_here_is_told_the_case_s_site(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SidecarConfig, "check", lambda self: None)

    config = app_module._crs_config_now(("shop.test",))

    assert config is not None
    assert config.host == "shop.test"


def test_a_case_crs_checked_only_in_part_puts_the_strip_up(
    qt_app: QApplication, tmp_path: Path, crs_here: SidecarConfig
) -> None:
    """Current CRS, stopped part way: not older, and still not the whole case."""
    stopped = {**crs_here.as_config(), "crs_replayed": 1, "crs_requests": 2, "crs_complete": False}

    window = _opened(qt_app, _case(tmp_path, stopped))

    assert window._older_crs.isVisible()
    assert "part" in window._older_crs.text()
    assert _run_again(window).isVisible()


def test_a_partial_case_is_named_even_where_crs_cannot_run_again(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The coverage is a fact about the case, true on any computer. Only the
    offer to run CRS again depends on this one."""
    monkeypatch.setattr(app_module, "_crs_config_now", lambda hosts: None)
    stopped = {
        **SidecarConfig().as_config(),
        "crs_replayed": 1,
        "crs_requests": 2,
        "crs_complete": False,
    }

    window = _opened(qt_app, _case(tmp_path, stopped))

    assert window._older_crs.isVisible()
    assert not [
        button
        for button in window._older_crs.findChildren(QPushButton)
        if button.text() == "Run CRS again" and button.isVisible()
    ]
