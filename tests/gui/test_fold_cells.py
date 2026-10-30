"""What a folded evidence row says, cell by cell. No Qt.

A folded row may only show a value every one of its lines shares. Where a looser
rule has folded lines that disagree, the cell says `mixed` and lists what it hides.
"""

from __future__ import annotations

from test_folding import brute_force, line

from zodiarc.gui.evidence_view import (
    ARROW_CLOSED,
    ARROW_OPEN,
    MIXED,
    cells_for,
    fold_cells,
    member_cells,
)
from zodiarc.gui.folding import FoldRule, fold
from zodiarc.style import EVIDENCE_MUTED


def test_a_run_of_one_is_drawn_exactly_as_today() -> None:
    lines = [line(1, "GET", "/", 200, 5)]
    (only,) = fold(lines, FoldRule.REQUEST_STATUS_SIZE)

    assert fold_cells(lines, only, decode=True, opened=False) == cells_for(lines[0], decode=True)


def test_a_folded_row_carries_the_arrow_the_count_and_the_shared_values() -> None:
    lines = brute_force()
    first = fold(lines, FoldRule.REQUEST_STATUS_SIZE)[0]

    line_cell, time_cell, request, status, size = fold_cells(
        lines, first, decode=True, opened=False
    )

    assert line_cell.text == f"{ARROW_CLOSED} excerpt.log:2014"
    assert line_cell.short == f"{ARROW_CLOSED} 2014"
    assert line_cell.tooltip == "5 lines: 2014 to 2018"
    assert time_cell.text == f"{lines[0].event.timestamp:%H:%M:%S}"
    assert time_cell.tooltip == (
        f"{lines[0].event.timestamp:%H:%M:%S} to {lines[4].event.timestamp:%H:%M:%S}"
    )
    assert request.text == "5x  POST /login"
    assert (status.text, size.text) == ("401", "7.6 KB")


def test_an_open_row_points_down() -> None:
    lines = brute_force()
    first = fold(lines, FoldRule.REQUEST_STATUS_SIZE)[0]

    assert fold_cells(lines, first, decode=True, opened=True)[0].text.startswith(ARROW_OPEN)


def test_values_the_lines_do_not_share_read_mixed_and_list_themselves() -> None:
    """The 302 a looser rule folds into the 401s is not hidden: the row says so."""
    lines = brute_force()
    (everything,) = fold(lines, FoldRule.REQUEST)

    status = fold_cells(lines, everything, decode=True, opened=False)[3]

    assert (status.text, status.italic) == (MIXED, True)
    assert status.tooltip == "401 x36 · 429 x2 · 302 x1"


def test_sizes_that_differ_are_listed_in_bytes() -> None:
    """7,744 and 7,740 bytes both read `7.6 KB`, so the list gives the bytes."""
    lines = brute_force()
    (everything,) = fold(lines, FoldRule.REQUEST)

    size = fold_cells(lines, everything, decode=True, opened=False)[4]

    assert size.text == MIXED
    assert size.tooltip.startswith("7,744 B x36")


def test_different_payloads_under_same_path_say_how_many_there_are() -> None:
    lines = [line(3133 + i, "GET", f"/search?q={i}", 200, 10) for i in range(46)]
    (everything,) = fold(lines, FoldRule.PATH)

    request = fold_cells(lines, everything, decode=True, opened=False)[2]

    assert request.text == "46x  GET /search?…"
    assert request.tooltip.startswith("46 different requests")


def test_the_shared_path_follows_the_decode_switch() -> None:
    """Every other request cell is decoded while decoding is on; this one was not."""
    lines = [line(1 + i, "GET", f"/files/a%20b?q={i}", 200, 10) for i in range(2)]
    (both,) = fold(lines, FoldRule.PATH)

    decoded = fold_cells(lines, both, decode=True, opened=False)[2]
    logged = fold_cells(lines, both, decode=False, opened=False)[2]

    assert decoded.text == "2x  GET /files/a b?…"
    assert logged.text == "2x  GET /files/a%20b?…"


def test_lines_from_two_files_are_named_with_their_file() -> None:
    lines = [
        line(9, "GET", "/a", 200, 1, file="a.log"),
        line(5, "GET", "/a", 200, 1, file="b.log"),
    ]
    (both,) = fold(lines, FoldRule.REQUEST_STATUS_SIZE)

    assert fold_cells(lines, both, decode=True, opened=False)[0].tooltip == (
        "2 lines, from a.log:9 to b.log:5"
    )


def test_lines_with_a_gap_say_from_rather_than_to() -> None:
    lines = [line(n, "GET", "/a", 200, 1) for n in (10, 11, 30)]
    (all_three,) = fold(lines, FoldRule.REQUEST_STATUS_SIZE)

    assert fold_cells(lines, all_three, decode=True, opened=False)[0].tooltip == (
        "3 lines, from 10 to 30"
    )


def test_a_member_row_is_its_own_line_in_the_quiet_colour() -> None:
    member = member_cells(brute_force()[1], decode=True)

    assert member[0].short.strip() == "2015"
    assert member[0].text.strip() == "excerpt.log:2015"
    assert member[2].colour == EVIDENCE_MUTED
    assert not member[2].bold
