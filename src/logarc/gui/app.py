"""The main window.

Holds no analysis. Every action here calls the same `logarc.case` and
`logarc.analysis` functions the CLI calls, on a worker thread, and displays what
comes back — which is what makes "anything the GUI can do is scriptable" true by
construction rather than by promise.
"""

from __future__ import annotations

import sys
import threading
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from logarc import __version__
from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.graph import GraphKind
from logarc.detect.crs import CrsEvidence
from logarc.gui._qt import required
from logarc.gui.canvas import ActivityCanvas
from logarc.gui.panels import ClientTable, EvidencePanel, LegendBar
from logarc.gui.workers import run_job
from logarc.ingest.pipeline import IngestCancelled
from logarc.report.html import render_report

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logarc.analysis import AnalysisResult
    from logarc.storage.base import IpSummary

__all__ = ["MainWindow", "main", "read_case", "reconstruct_client"]

#: Clients listed at once. The table is for choosing from, not for reading in
#: full; a case with a third of a million clients would otherwise freeze the
#: window building rows nobody scrolls to.
_CLIENT_LIMIT = 500

#: Source lines fetched for a selected activity. The episode keeps a bounded
#: sample of references anyway; this bounds what is read off disk per click.
_EVIDENCE_LIMIT = 25

#: Where the window remembers how it was left. One key so far: whether long
#: traces are folded. Worth persisting for the same reason an editor persists
#: word wrap — it is a reading preference, and being asked for it again every
#: launch is the annoyance the setting exists to remove.
_SETTINGS = ("logarc", "logarc")
_WRAP_KEY = "view/wrap_traces"


def _settings() -> QSettings:
    """Where the window's preferences live — the one place that decides.

    A function rather than the constructor spelled out at each call site, so
    there is a single seam a test can point somewhere harmless. `QSettings`
    resolves to `HKCU\\Software` on Windows, and a suite that wrote real
    preferences onto the machine running it would both dirty that machine and
    read its own leftovers back on the next run.
    """
    return QSettings(*_SETTINGS)


def _remembered_wrap() -> bool:
    """How traces were laid out last time, defaulting to folded.

    Normalised rather than trusted. Both stores hand this back as text — the
    registry keeps it as the `REG_SZ` "false", an ini file as the characters
    `false` — and a non-empty string is truthy, so reading it at face value
    turns wrapping back on for everyone who ever turned it off.
    """
    value = _settings().value(_WRAP_KEY, True)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"false", "0", ""}


# Module-level and Qt-free on purpose. These are the two decisions the window
# makes about a case, and while they lived inside worker closures the GUI could
# — and did — quietly disagree with the CLI about what a case contains. Out
# here they are callable without a display, so a test can hold both front ends
# to the same answer.
def read_case(path: Path) -> tuple[Sequence[IpSummary], CrsEvidence]:
    """Everything a freshly opened case needs, gathered in one visit.

    The CRS evidence is read here rather than per reconstruction because it is a
    property of the case, not of the client being looked at, and a case is
    opened once against many clicks.
    """
    with Case.open(path) as case:
        return (
            case.store.ip_summaries(limit=_CLIENT_LIMIT, order_by="requests"),
            case.crs_evidence(),
        )


def reconstruct_client(path: Path, client_ip: str, crs: CrsEvidence) -> AnalysisResult:
    """Reconstruct one client, applying whatever CRS contributed to the case."""
    with Case.open(path) as case:
        return analyse_ip(
            case.store,
            client_ip,
            crs=crs.index,
            crs_fingerprint=crs.fingerprint,
        )


class MainWindow(QMainWindow):
    """Open a case, pick a client, read what it did."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"logarc {__version__}")
        self.resize(1400, 880)

        self._case_path: Path | None = None
        self._result: AnalysisResult | None = None
        #: What CRS contributed to the open case. Empty until one is opened, so
        #: a reconstruction before then applies nothing rather than failing.
        self._crs = CrsEvidence(index=None, fingerprint=None)
        self._kind = GraphKind.TRACE
        self._stop: threading.Event | None = None

        self._clients = ClientTable()
        self._canvas = ActivityCanvas()
        self._legend = LegendBar()
        self._evidence = EvidencePanel()
        self._clients.client_chosen.connect(self._reconstruct)
        self._canvas.node_selected.connect(self._show_evidence)

        self._build_layout()
        self._build_menu()

        self._status = QLabel("Open a case, or ingest logs into a new one.")
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        self._cancel = QPushButton("Cancel")
        self._cancel.hide()
        self._cancel.clicked.connect(self._request_cancel)
        status_bar = required(self.statusBar())
        status_bar.addWidget(self._status, 1)
        status_bar.addPermanentWidget(self._progress)
        status_bar.addPermanentWidget(self._cancel)

    # -- construction ------------------------------------------------------

    def _build_layout(self) -> None:
        self._heading = QLabel("No client selected.")
        self._heading.setTextFormat(Qt.TextFormat.RichText)

        centre = QWidget()
        column = QVBoxLayout(centre)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self._heading)
        column.addWidget(self._canvas)
        column.addWidget(self._legend)

        # A floor, not just an opening size. `setSizes` is a suggestion the
        # splitter drops as soon as a child's size hint disagrees, and the
        # table's hint is small enough that the six columns were squeezed
        # back behind a scrollbar however wide the initial share was set.
        self._clients.setMinimumWidth(430)
        self._evidence.setMinimumWidth(330)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._clients)
        splitter.addWidget(centre)
        splitter.addWidget(self._evidence)
        splitter.setSizes([440, 560, 400])
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

        # Alt+Z, because that is what an editor uses for word wrap and this is
        # the same choice about the same trade: fold the long line and read it,
        # or keep it straight and scroll.
        self._wrap_action = self._add(view_menu, "&Wrap long traces", self._apply_wrap)
        self._wrap_action.setCheckable(True)
        self._wrap_action.setChecked(_remembered_wrap())
        self._wrap_action.setShortcut(QKeySequence("Alt+Z"))
        self._wrap_action.setStatusTip(
            "Fold a long session onto further rows so the captions stay readable, "
            "or lay it out on one line and pan along it."
        )
        self._canvas.set_wrap(self._wrap_action.isChecked())

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
        stop = threading.Event()

        def work(report: Callable[[str], None]) -> IngestCancelled | None:
            report(f"Ingesting {len(paths)} file(s)…")
            try:
                with Case.create(case_dir) as case:
                    case.ingest(
                        paths,
                        on_progress=lambda lines, _: report(f"{lines:,} lines read"),
                        should_cancel=stop.is_set,
                    )
            except IngestCancelled as cancelled:
                # Caught outside the `with`, so the case still sees the failure
                # on the way out and leaves itself un-finalised. Returned rather
                # than re-raised: a stop the investigator asked for should not
                # be presented as a crash.
                return cancelled
            return None

        self._busy(f"Ingesting into {case_dir}…", stop=stop)
        run_job(
            work,
            on_done=lambda outcome: self._ingest_finished(case_dir, outcome),
            on_error=self._report_error,
            on_progress=self._status.setText,
        )

    def _ingest_finished(self, case_dir: Path, outcome: object) -> None:
        if not isinstance(outcome, IngestCancelled):
            self._load_case(case_dir)
            return

        self._idle(f"Cancelled after {outcome.lines_read:,} lines.")
        QMessageBox.information(
            self,
            "Ingest cancelled",
            f"Stopped after {outcome.lines_read:,} lines.\n\n"
            f"{case_dir} holds what had been read by then and was not finalised, so it "
            "cannot be analysed. It is left in place rather than deleted — delete the "
            "folder yourself if you want to start over.",
        )

    def _load_case(self, path: Path) -> None:
        def work(report: Callable[[str], None]) -> Any:
            report(f"Opening {path}…")
            return read_case(path)

        self._busy(f"Opening {path}…")

        def done(loaded: Any) -> None:
            summaries, crs = loaded
            self._case_path = path
            self._crs = crs
            self._result = None
            self._canvas.show_graph_placeholder()
            self._evidence.clear()
            self._heading.setText("No client selected.")
            self._clients.show_clients(summaries)
            self._idle(
                f"{path} — {len(summaries):,} client(s) listed"
                + (", CRS applied" if crs.fingerprint else "")
            )

        run_job(work, on_done=done, on_error=self._report_error, on_progress=self._status.setText)

    # -- reconstruction ----------------------------------------------------

    def _reconstruct(self, client_ip: str) -> None:
        if self._case_path is None:
            return
        path = self._case_path
        # Read once here, on the interface thread, rather than from inside the
        # worker: the job must not reach back into window state while the window
        # is free to change it.
        crs = self._crs

        def work(report: Callable[[str], None]) -> AnalysisResult:
            report(f"Reconstructing {client_ip}…")
            return reconstruct_client(path, client_ip, crs)

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
        # Greyed out on the other view rather than hidden: a behaviour map is a
        # circle and has nothing to fold, and a live control that does nothing
        # reads as a fault. The choice itself is kept, and applies again here.
        self._wrap_action.setEnabled(True)
        self._redraw()

    def _show_behaviour(self) -> None:
        self._kind = GraphKind.BEHAVIOUR
        self._trace_action.setChecked(False)
        self._behaviour_action.setChecked(True)
        self._wrap_action.setEnabled(False)
        self._redraw()

    def _apply_wrap(self) -> None:
        """Fold long traces or stop folding them, and remember which."""
        wrap = self._wrap_action.isChecked()
        self._canvas.set_wrap(wrap)
        _settings().setValue(_WRAP_KEY, wrap)

    # -- evidence ----------------------------------------------------------

    def _show_evidence(self, node_id: str) -> None:
        if self._result is None or self._case_path is None:
            return
        # Ringed before the lookup, so the canvas answers the click even when
        # the episode behind it cannot be found and nothing fills the panel.
        self._canvas.highlight(node_id)
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

    def _busy(self, message: str, *, stop: threading.Event | None = None) -> None:
        """Show that work is running, and offer to stop it when it can be."""
        self._stop = stop
        self._status.setText(message)
        self._progress.show()
        self._cancel.setEnabled(True)
        self._cancel.setVisible(stop is not None)

    def _idle(self, message: str) -> None:
        self._stop = None
        self._status.setText(message)
        self._progress.hide()
        self._cancel.hide()

    def _request_cancel(self) -> None:
        if self._stop is None:  # pragma: no cover - the button is hidden then
            return
        self._stop.set()
        # Disabled rather than hidden: the ingest keeps running until the batch
        # in flight finishes, and a button that vanishes would suggest otherwise.
        self._cancel.setEnabled(False)
        self._status.setText("Stopping after the batch in flight…")

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
