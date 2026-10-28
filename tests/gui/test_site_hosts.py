"""Asking a case which domains are its own.

The second question this tool puts to a reader, and it is a different kind from
the CRS one. CRS asks for a preference; this asks for a fact only the reader
knows, and getting it wrong is quiet — a mistyped domain turns every ordinary
outbound link into a finding, with nothing on screen to say why. So the wording
has to carry what the answer is used for, and the dialog has to arrive already
holding the log's own answer rather than an empty box.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QDialog

from conftest import settled
from logarx.case import Case, SiteHostSuggestion
from logarx.gui.site_hosts import SiteHostsOffer

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

URL_LINES = [
    "shop.test:443 203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "
    '"GET /page?url=https://cdn.other.test/x.txt HTTP/1.1" 200 120 "-" "curl/8.0"',
]


def _case_with_urls(tmp_path: Path) -> Path:
    log = tmp_path / "vhost.log"
    log.write_text("\n".join(URL_LINES) + "\n", encoding="utf-8")
    case_dir = tmp_path / "case"
    with Case.create(case_dir) as case:
        case.ingest([log], log_format="apache-vhost-combined")
    return case_dir


def _suggested(*hosts: str, urls: int = 4) -> SiteHostSuggestion:
    return SiteHostSuggestion(hosts=hosts, urls_seen=urls, worth_asking=True)


def test_the_log_s_own_host_arrives_already_filled_in(qt_app: QApplication) -> None:
    """**This is what makes it one click rather than a chore.**

    The alternative was asking before the scan, where LogarX has read nothing
    and the box can only be empty. Proposing is the whole reason the question
    was worth adding at the end instead.
    """
    offer = SiteHostsOffer(_suggested("shop.example.com"))

    assert offer.answer() == ("shop.example.com",)


def test_every_host_the_log_names_is_offered_not_just_the_commonest(
    qt_app: QApplication,
) -> None:
    """A site behind a vhost log usually answers to two or three names, and
    `www.` is a different host to the comparison. Proposing one of them and
    silently dropping the rest would hand the reader a wrong answer that looks
    right."""
    offer = SiteHostsOffer(_suggested("shop.example.com", "www.shop.example.com"))

    assert offer.answer() == ("shop.example.com", "www.shop.example.com")


def test_a_log_that_names_no_host_asks_with_an_empty_box(qt_app: QApplication) -> None:
    """`apache-combined` records no Host, which is most logs. There is nothing
    to propose and the question is still worth putting — the reader knows the
    answer even though the log does not."""
    offer = SiteHostsOffer(_suggested())

    assert offer.answer() == ()
    assert "logs" in offer.spoken().lower() or "not record" in offer.spoken().lower()


def test_the_offer_says_what_the_answer_is_for(qt_app: QApplication) -> None:
    """Not "enter your domains" with no reason. A reader who does not know what
    it buys cannot tell whether getting it wrong matters."""
    words = SiteHostsOffer(_suggested("shop.example.com")).spoken().lower()

    assert "link" in words, "what it distinguishes is missing"


def test_the_offer_says_which_way_each_answer_fails(qt_app: QApplication) -> None:
    """Both directions, because they are not the same direction.

    Skipping is the safe one: nothing is named, both rules that read the answer
    stay silent, and the cost is findings. A domain of the site's left out — or
    mistyped, which leaves the real one out — is the other: its links are
    reported.

    The first version said "left out or wrong, those are missed — never
    invented", which is true of skipping and of nothing else. Measured
    2026-09-23: told `shop.tst` for `shop.test`, the site's own logo import is
    reported as remote file inclusion. A reader promised that a wrong answer is
    harmless answers casually, and a casual answer is the likeliest to be wrong.
    """
    lines = SiteHostsOffer(_suggested("shop.example.com")).spoken().lower().splitlines()

    assert any("leave out" in line and "reported" in line for line in lines)
    promises = [line for line in lines if "invented" in line]
    assert promises, "skipping is still safe, and a reader unsure of the answer needs to know"
    assert all("skip" in line for line in promises), "the promise holds for skipping alone"


def test_typing_over_the_suggestion_is_what_is_answered(qt_app: QApplication) -> None:
    offer = SiteHostsOffer(_suggested("shop.example.com"))

    offer.set_text("one.test, two.test")

    assert offer.answer() == ("one.test", "two.test")


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        # The separator people actually reach for, both of them.
        ("a.test, b.test", ("a.test", "b.test")),
        ("a.test b.test", ("a.test", "b.test")),
        ("a.test,b.test", ("a.test", "b.test")),
        # A whole URL pasted into a box that asked for a domain, which is the
        # ordinary mistake and is not a mistake worth punishing.
        ("https://a.test/help", ("https://a.test/help",)),
        # Nothing, or only separators, is no answer rather than a blank one.
        ("", ()),
        ("  ,  ", ()),
    ],
)
def test_what_counts_as_a_separator(
    qt_app: QApplication, typed: str, expected: tuple[str, ...]
) -> None:
    """Splitting is left generous and the reducing is left to `Case`, which
    already does it for the command line — one place that decides what a domain
    is, rather than two that can drift."""
    offer = SiteHostsOffer(_suggested())

    offer.set_text(typed)

    assert offer.answer() == expected


def test_a_ticked_box_is_what_stops_the_question_coming_back(qt_app: QApplication) -> None:
    """Global, not per case. The answer is already per case — it is saved with
    it — so a "remember" that meant "for this case" would mean nothing. What a
    reader wants to suppress is the question itself."""
    offer = SiteHostsOffer(_suggested("shop.example.com"))

    assert offer.remembered() is False

    offer.tick_remember()

    assert offer.remembered() is True


# -- what the window does with the answer ------------------------------------


def test_answering_saves_it_to_the_case(tmp_path: Path, qt_app: QApplication) -> None:
    """**The answer belongs to the case, not to the window that took it.**

    A reader who answers here and reruns from the command line tomorrow must
    get the same findings. That is the project's rule about the two front ends,
    and this is the only setting either of them can write.
    """
    from logarx.gui.app import MainWindow

    case_dir = _case_with_urls(tmp_path)
    window = MainWindow()
    try:
        offer = SiteHostsOffer(_suggested("shop.test"))
        window._site_hosts_offer = offer

        window._site_hosts_answered(case_dir, QDialog.DialogCode.Accepted)

        # Answering reloads the case, so there is a job in flight. Waiting for
        # it is the test saying it wants the end of that, not the way there.
        settled(qt_app)

        assert Case.open(case_dir).site_hosts == ("shop.test",)
    finally:
        window.close()


def test_skipping_leaves_the_case_unanswered(tmp_path: Path, qt_app: QApplication) -> None:
    """Skipped and never asked are the same state on purpose — the rule is
    silent either way, so nothing should be written that makes them differ."""
    from logarx.gui.app import MainWindow

    case_dir = _case_with_urls(tmp_path)
    window = MainWindow()
    try:
        window._site_hosts_offer = SiteHostsOffer(_suggested("shop.test"))

        window._site_hosts_answered(case_dir, QDialog.DialogCode.Rejected)

        # Every way out of the question opens the case, so there is a job in
        # flight whichever button was pressed.
        settled(qt_app)

        assert Case.open(case_dir).site_hosts == ()
    finally:
        window.close()


def test_crs_runs_only_once_the_domains_are_answered(tmp_path: Path, qt_app: QApplication) -> None:
    """CRS is chained behind the domain question rather than started beside it.

    It reads the site's own domain from the case to tell a link to the site
    from a link somewhere else (rule 931130), so a run started before the
    reader answered would be told the wrong host for its whole length.
    """
    from logarx.gui.app import MainWindow

    case_dir = _case_with_urls(tmp_path)
    window = MainWindow()
    asked: list[Path] = []
    try:
        window._start_crs = asked.append  # type: ignore[method-assign]
        window._site_hosts_offer = SiteHostsOffer(_suggested("shop.test"))

        window._site_hosts_answered(case_dir, QDialog.DialogCode.Rejected)
        settled(qt_app)

        assert asked == [case_dir]
    finally:
        window.close()
