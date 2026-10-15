"""Investigation queues with asynchronous paging and cancellable profiling."""

from __future__ import annotations

import threading
from html import escape
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabBar,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from logarc.case import Case
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.gui.recommendation import (
    SourceStatus,
    parse_anchor,
    render_recommendation,
    summary_for,
)
from logarc.gui.splitter import PanelSplitter
from logarc.gui.theme import PAD, TIGHT
from logarc.gui.workers import run_job
from logarc.style import plural
from logarc.triage.process import run_scan
from logarc.triage.profile import DEFAULT_POLICY, QueueName, RankedClient
from logarc.triage.scan import ScanCancelled, TriagePage, TriageProgress, TriageResult, read_page

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logarc.core.evidence import EvidenceRef

#: The two queues that analyse clients. Finding any one client, busy or quiet, is
#: the client list's job: it pages through and searches the whole case.
QUEUES: tuple[QueueName, ...] = ("suspicious", "unusual")
PAGE_SIZE = 100


class TriagePanel(QWidget):
    """Show reasons and source links; the worker owns every analysis decision."""

    investigate = pyqtSignal(str, object)

    #: How long a selection must stay put before its sources are read. Moving through
    #: the queue with the arrow keys would otherwise start a scan of the logs per row.
    SOURCE_CHECK_DELAY_MS = 250

    def __init__(self) -> None:
        super().__init__()
        self._generation = 0
        self._page_generation = 0
        self._stop: threading.Event | None = None
        self._request: tuple[Path, TimeWindow] | None = None
        self._result: TriageResult | None = None
        self._progress: TriageProgress | None = None
        self._rows: Sequence[RankedClient] = ()
        self._offset = 0
        self._shown: RankedClient | None = None
        self._expanded: frozenset[tuple[int, int]] = frozenset()
        self._opened: frozenset[int] = frozenset()
        self._context_open = False
        self._sources: dict[EvidenceRef, SourceStatus] = {}
        self._source_generation = 0
        self._source_error = ""
        self._source_timer = QTimer(self)
        self._source_timer.setSingleShot(True)
        self._source_timer.setInterval(self.SOURCE_CHECK_DELAY_MS)
        self._source_timer.timeout.connect(self._check_sources)
        self.queues = QTabBar()
        for name in ("Suspicious activity", "Unusual activity"):
            self.queues.addTab(name)
        self.queues.setExpanding(False)
        self.queues.currentChanged.connect(self._reset_page)
        self.notice = QLabel("Open a case to find where to start.")
        self.notice.setWordWrap(True)
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP addresses in this tab…")
        self.search.setClearButtonEnabled(True)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(self._load_page)
        self.search.textChanged.connect(self._search_changed)
        self.caption = QLabel()
        self.caption.setWordWrap(True)
        self.caption.setTextFormat(Qt.TextFormat.PlainText)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(("Rank", "IP address", "Key observation", "Requests"))
        row_header = self.table.verticalHeader()
        if row_header is not None:
            row_header.hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_details)
        # A single click selects a row so its reasons can be read; opening the client
        # is a deliberate act: double-click, or Inspect supporting requests.
        self.table.cellDoubleClicked.connect(lambda row, column: self._investigate())
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self._anchor)
        self.details.setPlaceholderText(
            "Select a recommendation to inspect its measurements and source references."
        )
        # The reader decides how much of the panel the recommendation gets: at a
        # fixed height either the queue or the reasons were cut off.
        self.split = PanelSplitter(Qt.Orientation.Vertical)
        self.split.addWidget(self.table)
        self.split.addWidget(self.details)
        self.split.setChildrenCollapsible(False)
        self.split.setStretchFactor(0, 1)
        self.split.setStretchFactor(1, 1)
        self.split.setSizes([1000, 1000])
        self.open_client = QPushButton("Inspect supporting requests")
        self.open_client.setEnabled(False)
        self.open_client.clicked.connect(self._investigate)
        self.previous_page = QPushButton("Previous")
        self.next_page = QPushButton("Next")
        self.previous_page.clicked.connect(lambda: self._page(-PAGE_SIZE))
        self.next_page.clicked.connect(lambda: self._page(PAGE_SIZE))
        self.cancel = QPushButton("Cancel scan")
        self.cancel.clicked.connect(self._cancel)
        self.cancel.hide()
        self.retry = QPushButton("Run scan")
        self.retry.clicked.connect(self._retry)
        self.retry.hide()
        controls = QHBoxLayout()
        for widget in (
            self.previous_page,
            self.next_page,
            self.open_client,
            self.cancel,
            self.retry,
        ):
            controls.addWidget(widget)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(PAD, TIGHT, PAD, TIGHT)
        layout.addWidget(self.notice)
        layout.addWidget(self.queues)
        layout.addWidget(self.search)
        layout.addWidget(self.caption)
        layout.addWidget(self.split, 1)
        layout.addLayout(controls)
        self._display(())

    def start(self, path: Path, window: TimeWindow = EVERYTHING) -> None:
        """Replace the requested case/range and ignore all previous callbacks."""
        self.shutdown()
        self.setEnabled(True)
        self._request = (path, window)
        self._offset = 0
        self.notice.setText(
            "Examining every IP in this time range. Findings are provisional. "
            "Use the client list to find any IP now."
        )
        self.caption.setText("Preparing the scan…")
        self.cancel.show()
        self.cancel.setEnabled(True)
        self.retry.hide()
        self._stop = stop = threading.Event()
        generation = self._generation

        def work(report: Callable[[object], None]) -> TriageResult | None:
            try:
                return run_scan(path, window=window, report=report, stop=stop)
            except ScanCancelled:
                return None

        def advanced(progress: TriageProgress) -> None:
            if generation != self._generation:
                return
            self._progress = progress
            self.notice.setText(
                f"Provisional: examined {progress.processed:,} of {progress.total:,} IPs. "
                "Use the client list to find any IP."
            )
            if self.queues.currentIndex() == 0 and not self.search.text():
                self._display(progress.findings)

        def done(result: TriageResult | None) -> None:
            if generation != self._generation:
                return
            self.cancel.hide()
            self._stop = None
            if result is None:
                self.notice.setText(
                    "Scan cancelled. Provisional findings cover only the examined IPs."
                )
                self.retry.show()
            else:
                self.show_result(result)

        def failed(message: str, detail: str) -> None:
            if generation == self._generation:
                self._stop = None
                self.cancel.hide()
                self.retry.show()
                self.notice.setText(
                    f"Prioritization unavailable: {message}. You can still select clients to reconstruct."
                )

        run_job(work, on_done=done, on_error=failed, on_advance=advanced)

    def shutdown(self) -> None:
        """Invalidate queued signals before stopping the worker that produced them."""
        self._generation += 1
        self._page_generation += 1
        self._search_timer.stop()
        if self._stop is not None:
            self._stop.set()
        self._stop = None
        self._request = None
        self._result = None
        self._progress = None
        self._display(())
        self.setEnabled(False)

    @property
    def result(self) -> TriageResult | None:
        """The completed index for the case and range last started, if there is one.

        `start` clears it before anything else, so it never answers for a range
        the window has since moved away from.
        """
        return self._result

    @property
    def progress(self) -> TriageProgress | None:
        """How far the running scan has got, as last reported."""
        return self._progress

    @property
    def scanning(self) -> bool:
        """Whether a scan is running, including one that is being stopped."""
        return self._stop is not None

    def _cancel(self) -> None:
        if self._stop is not None:
            self._stop.set()
            self.cancel.setEnabled(False)
            self.notice.setText("Stopping the prioritization scan…")

    def _retry(self) -> None:
        if self._request is not None:
            self.start(*self._request)

    def show_result(self, result: TriageResult) -> None:
        self._result = result
        self.cancel.hide()
        self.retry.hide()
        crs = "CRS evidence included" if result.crs_present else "CRS not applied"
        self.notice.setText(
            f"Examined all {result.clients:,} IPs. {crs}. "
            "Indicators do not establish intent or compromise. An IP may represent several clients."
        )
        self._reset_page()

    def _reset_page(self) -> None:
        self._search_timer.stop()
        self._offset = 0
        self._load_page()

    def _search_changed(self) -> None:
        self._page_generation += 1
        self._offset = 0
        self._display(())
        self._search_timer.start()

    def _page(self, delta: int) -> None:
        self._offset = max(0, self._offset + delta)
        self._load_page()

    def _load_page(self) -> None:
        self._page_generation += 1
        generation = self._page_generation
        self._display(())
        queue = QUEUES[self.queues.currentIndex()]
        if self._result is None:
            self.caption.setText(
                "Use the client list to find any IP while recommendations are being prepared. "
                "Unusualness comparisons need a completed scan."
            )
            return
        result = self._result
        query, offset = self.search.text(), self._offset

        def done(page: TriagePage) -> None:
            if generation != self._page_generation:
                return
            self._display(page.rows)
            self.previous_page.setEnabled(page.offset > 0)
            self.next_page.setEnabled(page.offset + len(page.rows) < page.total)
            if page.rows:
                text = (
                    f"Showing {page.offset + 1:,}\u2013{page.offset + len(page.rows):,} "
                    f"of {plural(page.total, 'IP')} with {queue} activity"
                )
            else:
                text = f"No IPs with {queue} activity"
            if query.strip():
                text += " (matching your search)"
            elif not page.rows:
                text += " in this time range"
            if queue == "unusual":
                policy = DEFAULT_POLICY
                if result.eligible < policy.minimum_population:
                    text = f"Need {policy.minimum_population} clients with at least {policy.minimum_requests} requests; this range has {result.eligible}."
                else:
                    text += ". Unusual within this case; legitimate activity can be unusual. Missing fields are excluded from comparisons."
            elif queue == "suspicious" and not page.total:
                text += ". This does not establish that the traffic is safe."
            self.caption.setText(text)

        def failed(message: str, detail: str) -> None:
            if generation == self._page_generation:
                self.caption.setText(f"Could not read priorities: {message}")

        run_job(
            lambda report: read_page(
                result.path, queue, query=query, offset=offset, limit=PAGE_SIZE
            ),
            on_done=done,
            on_error=failed,
        )

    def _display(self, rows: Sequence[RankedClient]) -> None:
        self._rows = rows
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        self.details.clear()
        self._shown = None
        self.open_client.setEnabled(False)
        self.previous_page.setEnabled(False)
        self.next_page.setEnabled(False)
        for index, row in enumerate(rows):
            values = (
                str(row.rank or self._offset + index + 1),
                row.profile.client_ip,
                summary_for(row),
                f"{row.profile.requests:,}",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(index, column, item)

    def _show_details(self) -> None:
        index = self.table.currentRow()
        if index < 0 or index >= len(self._rows):
            return
        row = self._rows[index]
        if row is not self._shown:
            self._shown, self._expanded, self._sources = row, frozenset(), {}
            self._opened = frozenset()
            self._context_open = False
            self._source_error = ""
            self._source_generation += 1
            self._source_timer.start()
        self._render()
        self.open_client.setEnabled(True)

    def _render(self) -> None:
        """Draw the shown recommendation, cutting request paths to two lines of the area."""
        if self._shown is None:
            return
        metrics = QFontMetrics(self.details.font())
        width = (self.details.viewport() or self.details).width()
        path_chars = max(20, 2 * max(width - 24, 0) // max(metrics.averageCharWidth(), 1))
        html = render_recommendation(
            self._shown,
            self._sources,
            path_chars=path_chars,
            expanded=self._expanded,
            opened=self._opened,
            show_context=self._context_open,
        )
        if self._source_error:
            html = (
                f"<p>Sources could not be checked: {escape(self._source_error)}. Examples "
                "still open; reconstruction reports any line it cannot read.</p>" + html
            )
        # Redrawing replaces the document, which would otherwise return the reader
        # to the top whenever a source check lands or a path is expanded.
        bar = self.details.verticalScrollBar()
        place = bar.value() if bar is not None else 0
        self.details.setHtml(html)
        if bar is not None:
            bar.setValue(place)

    def _check_sources(self) -> None:
        """Read the lines behind the shown recommendation off the interface thread, to say
        which cannot be opened and which come from a source changed since ingest."""
        row = self._shown
        generation = self._source_generation
        if row is None or self._request is None:
            return
        path = self._request[0]
        refs = tuple(
            dict.fromkeys(
                [ref for reason in row.reasons for ref in reason.evidence]
                + [item.evidence for reason in row.reasons for item in reason.examples]
            )
        )

        def work(_: Callable[[object], None]) -> dict[EvidenceRef, SourceStatus]:
            if generation != self._source_generation:
                return {}
            with Case.open(path) as case:
                lines = case.read_evidence(refs)
            return {
                line.ref: SourceStatus(line.note, can_open=line.text is not None)
                for line in lines
                if line.note
            }

        def done(sources: dict[EvidenceRef, SourceStatus]) -> None:
            if generation == self._source_generation and row is self._shown:
                self._sources = sources
                self._render()

        def failed(message: str, detail: str) -> None:
            if generation == self._source_generation and row is self._shown:
                self._source_error = message
                self._render()

        run_job(work, on_done=done, on_error=failed)

    def _anchor(self, url: QUrl) -> None:
        """Toggle detail sections, inspect evidence, or show an example's full path."""
        parsed = parse_anchor(url)
        row = self._shown
        if parsed is None or row is None:
            return
        kind, number, index = parsed
        if kind == "context":
            self._context_open = not self._context_open
            self._render()
            return
        if number >= len(row.reasons):
            return
        if kind == "details":
            self._opened = self._opened.symmetric_difference({number})
            self._render()
            return
        reason = row.reasons[number]
        if kind == "reason":
            self.investigate.emit(row.profile.client_ip, reason.evidence)
        elif index < len(reason.examples):
            example = reason.examples[index]
            if kind == "expand":
                self._expanded = self._expanded | {(number, index)}
                self._render()
            elif self._sources.get(example.evidence, SourceStatus("", True)).can_open:
                self.investigate.emit(row.profile.client_ip, (example.evidence,))

    def _investigate(self) -> None:
        index = self.table.currentRow()
        if 0 <= index < len(self._rows):
            row = self._rows[index]
            refs = row.reasons[0].evidence if row.reasons else ()
            self.investigate.emit(row.profile.client_ip, refs)
