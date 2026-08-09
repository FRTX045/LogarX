"""The main window.

Holds no analysis. Every action here calls the same `logarc.case` and
`logarc.analysis` functions the CLI calls, on a worker thread, and displays what
comes back — which is what makes "anything the GUI can do is scriptable" true by
construction rather than by promise.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from logarc import __version__
from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.graph import GraphKind
from logarc.gui._qt import required
from logarc.gui.canvas import ActivityCanvas
from logarc.gui.panels import ClientTable, EvidencePanel
from logarc.gui.workers import run_job
from logarc.report.html import render_report

if TYPE_CHECKING:
    from collections.abc import Callable

    from logarc.analysis import AnalysisResult

__all__ = ["MainWindow", "main"]

#: Clients listed at once. The table is for choosing from, not for reading in
#: full; a case with a third of a million clients would otherwise freeze the
#: window building rows nobody scrolls to.
_CLIENT_LIMIT = 500

#: Source lines fetched for a selected activity. The episode keeps a bounded
#: sample of references anyway; this bounds what is read off disk per click.
_EVIDENCE_LIMIT = 25


class MainWindow(QMainWindow):
    """Open a case, pick a client, read what it did."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"logarc {__version__}")
        self.resize(1400, 880)

        self._case_path: Path | None = None
        self._result: AnalysisResult | None = None
        self._kind = GraphKind.TRACE

        self._clients = ClientTable()
        self._canvas = ActivityCanvas()
        self._evidence = EvidencePanel()
        self._clients.client_chosen.connect(self._reconstruct)
        self._canvas.node_selected.connect(self._show_evidence)

        self._build_layout()
        self._build_menu()

        self._status = QLabel("Open a case, or ingest logs into a new one.")
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        status_bar = required(self.statusBar())
        status_bar.addWidget(self._status, 1)
        status_bar.addPermanentWidget(self._progress)

    # -- construction ------------------------------------------------------

    def _build_layout(self) -> None:
        self._heading = QLabel("No client selected.")
        self._heading.setTextFormat(Qt.TextFormat.RichText)

        centre = QWidget()
        column = QVBoxLayout(centre)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self._heading)
        column.addWidget(self._canvas)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._clients)
        splitter.addWidget(centre)
        splitter.addWidget(self._evidence)
        splitter.setSizes([330, 720, 350])
        self.setCentralWidget(splitter)

    def _build_menu(self) -> None:
        menu_bar = required(self.menuBar())
        case_menu = required(menu_bar.addMenu("&Case"))
        self._add(case_menu, "&Open case…", self._open_case, QKeySequence.StandardKey.Open)
        self._add(case_menu, "Ingest logs into a &new case…", self._ingest_new_case)
        case_menu.addSeparator()
        self._add(case_menu, "E&xit", self.close, QKeySequence.StandardKey.Quit)

        view_menu = required(menu_bar.addMenu("&View"))
        self._trace_action = self._add(view_menu, "&Trace (chronological)", self._show_trace)
        self._behaviour_action = self._add(view_menu, "&Behaviour map", self._show_behaviour)
        for action in (self._trace_action, self._behaviour_action):
            action.setCheckable(True)
        self._trace_action.setChecked(True)
        view_menu.addSeparator()
        self._add(view_menu, "&Fit to window", self._canvas.fit)

        export_menu = required(menu_bar.addMenu("&Export"))
        self._add(export_menu, "&HTML report…", lambda: self._export("html"))
        self._add(export_menu, "&JSON graph…", lambda: self._export("json"))
        self._add(export_menu, "&PNG image…", lambda: self._export("png"))

    def _add(
        self,
        menu: QMenu,
        text: str,
        # `object` rather than `None`: QWidget.close returns a bool, and a menu
        # action does not care what its slot hands back.
        slot: Callable[[], object],
        shortcut: QKeySequence.StandardKey | None = None,
    ) -> QAction:
        action = QAction(text, self)
        action.triggered.connect(slot)
        if shortcut is not None:
            action.setShortcut(shortcut)
        menu.addAction(action)
        return action

    # -- case --------------------------------------------------------------

    def _open_case(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Open case directory")
        if chosen:
            self._load_case(Path(chosen))

    def _ingest_new_case(self) -> None:
        logs, _ = QFileDialog.getOpenFileNames(
            self, "Choose log files", "", "Logs (*.log *.txt *.gz *.bz2);;All files (*)"
        )
        if not logs:
            return
        target = QFileDialog.getExistingDirectory(self, "Choose an empty folder for the case")
        if not target:
            return

        paths = [Path(item) for item in logs]
        case_dir = Path(target)

        def work(report: Callable[[str], None]) -> None:
            report(f"Ingesting {len(paths)} file(s)…")
            with Case.create(case_dir) as case:
                case.ingest(paths, on_progress=lambda lines, _: report(f"{lines:,} lines read"))

        self._busy(f"Ingesting into {case_dir}…")
        run_job(
            work,
            on_done=lambda _: self._load_case(case_dir),
            on_error=self._report_error,
            on_progress=self._status.setText,
        )

    def _load_case(self, path: Path) -> None:
        def work(report: Callable[[str], None]) -> Any:
            report(f"Opening {path}…")
            with Case.open(path) as case:
                return case.store.ip_summaries(limit=_CLIENT_LIMIT, order_by="requests")

        self._busy(f"Opening {path}…")

        def done(summaries: Any) -> None:
            self._case_path = path
            self._result = None
            self._canvas.show_graph_placeholder()
            self._evidence.clear()
            self._heading.setText("No client selected.")
            self._clients.show_clients(summaries)
            self._idle(f"{path} — {len(summaries):,} client(s) listed")

        run_job(work, on_done=done, on_error=self._report_error, on_progress=self._status.setText)

    # -- reconstruction ----------------------------------------------------

    def _reconstruct(self, client_ip: str) -> None:
        if self._case_path is None:
            return
        path = self._case_path

        def work(report: Callable[[str], None]) -> AnalysisResult:
            report(f"Reconstructing {client_ip}…")
            with Case.open(path) as case:
                return analyse_ip(case.store, client_ip)

        self._busy(f"Reconstructing {client_ip}…")

        def done(result: AnalysisResult) -> None:
            self._result = result
            self._evidence.clear()
            self._heading.setText(
                f"<b>{result.client_ip}</b> — {result.request_count:,} requests across "
                f"{len(result.sessions)} session(s), reduced to "
                f"{len(result.episodes)} activities"
            )
            self._redraw()
            self._idle(f"{client_ip}: {len(result.episodes)} activities")

        run_job(work, on_done=done, on_error=self._report_error, on_progress=self._status.setText)

    def _redraw(self) -> None:
        if self._result is None:
            return
        graph = self._result.trace if self._kind is GraphKind.TRACE else self._result.behaviour
        self._canvas.show_graph(graph)

    def _show_trace(self) -> None:
        self._kind = GraphKind.TRACE
        self._trace_action.setChecked(True)
        self._behaviour_action.setChecked(False)
        self._redraw()

    def _show_behaviour(self) -> None:
        self._kind = GraphKind.BEHAVIOUR
        self._trace_action.setChecked(False)
        self._behaviour_action.setChecked(True)
        self._redraw()

    # -- evidence ----------------------------------------------------------

    def _show_evidence(self, node_id: str) -> None:
        if self._result is None or self._case_path is None:
            return
        graph = self._result.trace if self._kind is GraphKind.TRACE else self._result.behaviour
        node = next((item for item in graph.nodes if item.node_id == node_id), None)
        if node is None:
            return

        episode = next(
            (item for item in self._result.episodes if item.episode_id in node.episode_ids),
            None,
        )
        if episode is None:
            return

        path = self._case_path
        refs = node.evidence[:_EVIDENCE_LIMIT]

        def work(_: Callable[[str], None]) -> Any:
            with Case.open(path) as case:
                return case.read_evidence(refs)

        run_job(
            work,
            on_done=lambda lines: self._evidence.show_evidence(episode, lines),
            on_error=self._report_error,
        )

    # -- export ------------------------------------------------------------

    def _export(self, kind: str) -> None:
        if self._result is None or self._case_path is None:
            QMessageBox.information(self, "Nothing to export", "Reconstruct a client first.")
            return

        filters = {
            "html": ("HTML report", "report.html", "HTML (*.html)"),
            "json": ("JSON graph", "graph.json", "JSON (*.json)"),
            "png": ("PNG image", "graph.png", "PNG (*.png)"),
        }
        title, suggested, mask = filters[kind]
        chosen, _ = QFileDialog.getSaveFileName(self, f"Export {title}", suggested, mask)
        if not chosen:
            return

        target = Path(chosen)
        result = self._result
        case_path = self._case_path

        if kind == "png":
            self._export_png(target)
            return

        def work(_: Callable[[str], None]) -> str:
            if kind == "json":
                import json

                target.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
            else:
                with Case.open(case_path) as case:
                    target.write_text(render_report(result, case.manifest), encoding="utf-8")
            return str(target)

        run_job(
            work,
            on_done=lambda written: self._idle(f"Written to {written}"),
            on_error=self._report_error,
        )

    def _export_png(self, target: Path) -> None:
        """Rendered here rather than on a worker: painting needs the GUI thread."""
        from PyQt6.QtGui import QImage, QPainter

        scene = self._canvas.graph_scene
        bounds = scene.sceneRect()
        image = QImage(
            int(bounds.width()) or 1, int(bounds.height()) or 1, QImage.Format.Format_ARGB32
        )
        image.fill(Qt.GlobalColor.white)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        scene.render(painter)
        painter.end()
        if image.save(str(target)):
            self._idle(f"Written to {target}")
        else:
            self._report_error(f"Could not write {target}", "")

    # -- status ------------------------------------------------------------

    def _busy(self, message: str) -> None:
        self._status.setText(message)
        self._progress.show()

    def _idle(self, message: str) -> None:
        self._status.setText(message)
        self._progress.hide()

    def _report_error(self, message: str, detail: str) -> None:
        self._progress.hide()
        self._status.setText(message)
        if detail:
            # The window gets a sentence; the terminal keeps the traceback, so a
            # failure is never only a dialog nobody wrote down.
            print(detail, file=sys.stderr)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("logarc")
        box.setText(message)
        if detail:
            box.setDetailedText(detail)
        box.exec()


def main() -> int:
    """Entry point for the `logarc-gui` command."""
    app = QApplication(sys.argv)
    app.setApplicationName("logarc")
    try:
        window = MainWindow()
    except Exception:
        traceback.print_exc()
        return 1
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
