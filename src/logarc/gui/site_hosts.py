"""Asking a case which domains belong to the site it came from.

The answer decides whether a URL in a query parameter points somewhere the site
does not own — the only thing separating remote file inclusion from a share
link, an OAuth callback or a login redirect, because the request is
`GET /page?url=…` either way. `rfi_offsite_url` reads it directly, and
enrichment hands it to CRS, whose off-domain rule 931130 names nothing until
it has been told.

Two decisions shape this dialog, and both come from what it is asking for.

**It arrives already answered.** The log usually names its own host, so the box
holds it and the reader confirms. That is the whole reason the question is put
*after* the scan: asked before one, logarc has read nothing and can only offer
an empty box.

**It says which way each answer fails, and they are opposite ways.** Skipping
is safe: both rules stay silent and the cost is findings. A domain of the
site's left out, or mistyped, is not — its own links become findings, quietly,
with nothing on screen to explain them. The first version of this dialog
promised that a wrong answer only cost findings; measured on 2026-09-23, a
mistyped domain reported the site's own logo import as remote file inclusion.
So it now says both, and says the safe one is Skip.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from logarc.gui._qt import required
from logarc.gui.crs import _COST, _GAIN, _quiet, _side, _Spoken, _titled, _wrapped
from logarc.gui.theme import GAP, ROOM, TIGHT, colour_text, mono_font
from logarc.style import THEME

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from logarc.case import SiteHostSuggestion

__all__ = ["SiteHostsOffer"]

#: What separates one domain from the next in the box.
#:
#: Commas and spaces both, because people reach for either and neither is wrong.
#: Nothing else is stripped here — a reader who pastes a whole URL has answered
#: the question, and `Case.set_site_hosts` reduces it the same way it reduces
#: what the command line is given. One place decides what a domain is.
_SEPARATORS = re.compile(r"[,\s]+")


class SiteHostsOffer(_Spoken):
    """Asked once, after a scan, and only where the answer would change something."""

    def __init__(self, suggestion: SiteHostSuggestion, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Is this your site?")
        self.setFixedWidth(430)
        # Modal to the reader, non-blocking to the caller — `setModal` plus
        # `show()`, the way `CrsUnavailable` and `IngestCard` do it. `exec()` would
        # block the thread that just finished an ingest.
        self.setModal(True)

        self._field = QLineEdit(", ".join(suggestion.hosts))
        self._field.setFont(mono_font())
        self._field.setPlaceholderText("example.com, www.example.com")
        colour_text(self._field, THEME.identity)

        self._quiet_it = QCheckBox("Don't ask this again")

        buttons = QDialogButtonBox()
        yes = required(buttons.addButton("Use these", QDialogButtonBox.ButtonRole.AcceptRole))
        yes.setDefault(True)
        buttons.addButton("Skip", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        trade = QVBoxLayout()
        trade.setSpacing(TIGHT)
        # Names the discrimination, not just the benefit. A reader who is only
        # told this "finds more attacks" has no way to judge whether getting the
        # answer wrong matters; one who is told it separates a link to your own
        # site from a link somewhere else knows exactly what they are supplying.
        trade.addWidget(
            _side("+", _GAIN, "Catches a request that fetches a file from a link somewhere else")
        )
        trade.addWidget(
            _side(
                "\N{MINUS SIGN}",
                _COST,
                "Leave out a domain of yours, and links to it are reported as attacks",
            )
        )

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        stack.addWidget(_titled("Is this your site?"))
        stack.addWidget(self._lede(suggestion))
        stack.addWidget(self._field)
        stack.addLayout(trade)
        # The one direction that cannot go wrong, said where somebody unsure
        # of the answer is deciding whether to give one.
        stack.addWidget(
            _quiet("Not sure? Skip — nothing is invented, and the case stays as it is.")
        )
        stack.addWidget(self._quiet_it)
        stack.addWidget(buttons)

    @staticmethod
    def _lede(suggestion: SiteHostSuggestion) -> QLabel:
        """The one line above the box, which differs by what the log gave up.

        Three cases and they are genuinely different questions. With a host the
        reader is confirming; with several they are pruning; with none they are
        answering from their own knowledge, and saying that the log records no
        host is what stops an empty box reading as a bug.
        """
        if not suggestion.hosts:
            text = (
                "This log does not record which host each request was for — most "
                "do not. Name the domains this site answers to."
            )
        elif len(suggestion.hosts) == 1:
            text = "Every request in this log names the same host."
        else:
            text = "This log names more than one host. Keep the ones that are yours."
        label = _wrapped(text)
        label.setStyleSheet(f"color: {THEME.ink};")
        return label

    def answer(self) -> tuple[str, ...]:
        """What is in the box, split but not otherwise touched.

        Reducing is `Case.set_site_hosts`'s job, so the dialog and the command
        line cannot come to different conclusions about what `https://a.test/`
        means.
        """
        return tuple(part for part in _SEPARATORS.split(self._field.text().strip()) if part)

    def set_text(self, text: str) -> None:
        """Type over the suggestion. Here so a test can, as a reader would."""
        self._field.setText(text)

    def remembered(self) -> bool:
        """Whether to stop putting this question at all.

        Global rather than per case: the *answer* is already per case, saved
        with it, so a "remember" meaning "for this case" would mean nothing.
        What a reader wants to suppress is the question.
        """
        return self._quiet_it.isChecked()

    def tick_remember(self) -> None:
        self._quiet_it.setChecked(True)
