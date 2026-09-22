"""Investigation queues with asynchronous paging and cancellable profiling."""

from __future__ import annotations

import threading
from html import escape
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal
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
from logarc.gui.theme import PAD, TIGHT
from logarc.gui.workers import run_job
from logarc.storage.base import IpSummary, IpSummaryPage
from logarc.triage.process import run_scan
from logarc.triage.profile import DEFAULT_POLICY, FEATURES, QueueName, RankedClient
from logarc.triage.scan import ScanCancelled, TriagePage, TriageProgress, TriageResult, read_page

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

QUEUES: tuple[QueueName, ...] = ("suspicious", "unusual", "all")
PAGE_SIZE = 100


class TriagePanel(QWidget):
    """Show reasons and source links; the worker owns every analysis decision."""

    investigate = pyqtSignal(str, object)

    def __init__(self) -> None:
        super().__init__()
        self._generation = 0
        self._page_generation = 0
        self._stop: threading.Event | None = None
        self._request: tuple[Path, TimeWindow] | None = None
        self._result: TriageResult | None = None
        self._rows: Sequence[RankedClient | IpSummary] = ()
        self._offset = 0
        self.queues = QTabBar()
        for name in ("Suspicious activity", "Unusual activity", "All clients"):
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
        self.table.setHorizontalHeaderLabels(("Rank", "IP address", "Why look here", "Requests"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_details)
        self.table.cellClicked.connect(self._reason_clicked)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self._reason_link)
        self.details.setPlaceholderText(
            "Select a recommendation to inspect its measurements and source references."
        )
        self.details.setMaximumHeight(200)
        self.open_client = QPushButton("Open supporting evidence")
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
        layout.addWidget(self.table, 1)
        layout.addWidget(self.details)
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
            "Use All clients to search the full population now."
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
            self.notice.setText(
                f"Provisional: examined {progress.processed:,} of {progress.total:,} IPs. "
                "Use All clients for full-population search."
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
        if self.queues.currentIndex() == 2:
            self._load_page()

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
        self._display(())
        self.setEnabled(False)

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
        if queue == "all" and self._request is not None:
            self._load_summaries(generation)
            return
        if self._result is None:
            self.caption.setText(
                "Use All clients to search every IP while recommendations are being prepared. "
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
            text = f"{page.offset + 1 if page.rows else 0:,}-{page.offset + len(page.rows):,} of {page.total:,} matching IPs"
            if queue == "unusual":
                policy = DEFAULT_POLICY
                if result.eligible < policy.minimum_population:
                    text = f"Need {policy.minimum_population} clients with at least {policy.minimum_requests} requests; this range has {result.eligible}."
                else:
                    text += ". Unusual within this case; legitimate activity can be unusual. Missing fields are excluded from comparisons."
            elif queue == "suspicious" and not page.total:
                text += ". No matching hostile detections; this does not establish that the traffic is safe."
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

    def _load_summaries(self, generation: int) -> None:
        assert self._request is not None
        path, window = self._request
        query, offset = self.search.text(), self._offset
        self.caption.setText("Searching all clients…")

        def work(report: Callable[[object], None]) -> IpSummaryPage:
            with Case.open(path) as case:
                return case.store.ip_summary_page(
                    query=query, offset=offset, limit=PAGE_SIZE, window=window
                )

        def done(page: IpSummaryPage) -> None:
            if generation != self._page_generation:
                return
            self._display(page.rows)
            self.previous_page.setEnabled(page.offset > 0)
            self.next_page.setEnabled(page.offset + len(page.rows) < page.total)
            self.caption.setText(
                f"{page.offset + 1 if page.rows else 0:,}-{page.offset + len(page.rows):,} "
                f"of {page.total:,} matching IPs. Positions follow request count across this range. "
                "Open a client for reconstruction and detection details."
            )

        def failed(message: str, detail: str) -> None:
            if generation == self._page_generation:
                self.caption.setText(f"Could not search clients: {message}")

        run_job(work, on_done=done, on_error=failed)

    def _display(self, rows: Sequence[RankedClient | IpSummary]) -> None:
        self._rows = rows
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        self.details.clear()
        self.open_client.setEnabled(False)
        self.previous_page.setEnabled(False)
        self.next_page.setEnabled(False)
        for index, row in enumerate(rows):
            values = (
                (
                    str(row.position),
                    row.client_ip,
                    "Not yet analyzed here; open reconstruction"
                    if self._result is None
                    else "Open reconstruction for detection details",
                    f"{row.request_count:,}",
                )
                if isinstance(row, IpSummary)
                else (
                    str(row.rank or self._offset + index + 1),
                    row.profile.client_ip,
                    row.reasons[0].text if row.reasons else "No hostile detection",
                    f"{row.profile.requests:,}",
                )
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
        if isinstance(row, IpSummary):
            self.details.setPlainText(
                f"{row.client_ip}\n{row.request_count:,} requests; {row.distinct_paths:,} distinct paths.\n"
                f"First seen: {row.first_seen}; last seen: {row.last_seen}.\n"
                "This summary does not assert that there are no hostile detections. "
                "Open reconstruction to analyze this client and inspect source evidence."
            )
            self.open_client.setEnabled(True)
            return
        profile = row.profile
        reasons = [f"<b>{escape(profile.client_ip)}</b>"]
        for number, reason in enumerate(row.reasons):
            reasons.append(
                f'<p><a href="reason:{number}">{escape(reason.text)}</a><br>'
                + "Sample source lines: "
                + escape(", ".join(map(str, reason.evidence)))
                + "</p>"
            )
        lines = ["Recorded measurements:"]
        lines.extend(f"{FEATURES[name]}: {value:,.3g}" for name, value in profile.features.items())
        lines.extend(("", "Field coverage:"))
        lines.extend(
            f"{name}: {count:,}/{profile.requests:,} requests"
            for name, count in profile.coverage.items()
        )
        lines.append(
            "Status responses: "
            + (
                ", ".join(f"{status}: {count}" for status, count in profile.statuses.items())
                or "not recorded"
            )
        )
        lines.append(
            "Response codes and sizes do not prove attack success. Source references are samples, not the complete supporting set."
        )
        self.details.setHtml("".join(reasons) + "<br>".join(escape(line) for line in lines))
        self.open_client.setEnabled(True)

    def _reason_clicked(self, row: int, column: int) -> None:
        if column == 2:
            self._investigate()

    def _reason_link(self, url: QUrl) -> None:
        index = self.table.currentRow()
        if url.scheme() != "reason" or not url.path().isdigit():
            return
        reason = int(url.path())
        if 0 <= index < len(self._rows):
            row = self._rows[index]
            if isinstance(row, RankedClient) and reason < len(row.reasons):
                self.investigate.emit(row.profile.client_ip, row.reasons[reason].evidence)

    def _investigate(self) -> None:
        index = self.table.currentRow()
        if 0 <= index < len(self._rows):
            row = self._rows[index]
            if isinstance(row, IpSummary):
                self.investigate.emit(row.client_ip, ())
                return
            refs = row.reasons[0].evidence if row.reasons else ()
            self.investigate.emit(row.profile.client_ip, refs)
