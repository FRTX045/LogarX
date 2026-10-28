"""What the window says about the stretch of time it is showing.

Qt-free, like `gui/arrangement.py` and `gui/recent.py`: the words a control puts
on screen are a decision, and a decision should be checkable without a display.
"""

from __future__ import annotations

from datetime import UTC, datetime

from logarx.core.window import EVERYTHING, TimeWindow
from logarx.timerange import nobody_here, spoken, summary

FROM = datetime(2024, 5, 2, 1, 25, 0, tzinfo=UTC)
TO = datetime(2024, 5, 2, 2, 0, 0, tzinfo=UTC)
WINDOW = TimeWindow(FROM, TO)


# -- what the control says it is showing -----------------------------------


def test_the_whole_case_says_so_rather_than_counting_itself() -> None:
    """`9,910 of 9,910 clients` is a program telling you it has done nothing.
    The unfiltered state is the ordinary one and should read as ordinary."""
    assert summary(EVERYTHING, clients=9910, all_clients=9910) == "All time"


def test_a_window_says_how_much_of_the_case_is_left() -> None:
    assert summary(WINDOW, clients=155, all_clients=9910) == "155 of 9,910 clients"


def test_the_request_count_joins_the_sentence_when_there_is_one() -> None:
    """A client is selected, so the window can say what the filter did to the
    list *and* to the graph — the two numbers that must agree."""
    said = summary(WINDOW, clients=155, all_clients=9910, requests=16, all_requests=19)

    assert said == "155 of 9,910 clients · 16 of 19 requests"


def test_the_noun_agrees_with_the_total_not_the_part() -> None:
    """`1 of 9,910 client` is not English. The phrase is about the total."""
    assert summary(WINDOW, clients=1, all_clients=9910) == "1 of 9,910 clients"

    said = summary(WINDOW, clients=1, all_clients=19, requests=1, all_requests=19)
    assert said.endswith("1 of 19 requests")


def test_a_total_of_one_is_written_in_the_singular() -> None:
    assert summary(WINDOW, clients=1, all_clients=1) == "1 of 1 client"


def test_thousands_are_separated_so_the_numbers_can_be_read() -> None:
    said = summary(WINDOW, clients=1234, all_clients=567890)

    assert "1,234" in said
    assert "567,890" in said


def test_nothing_left_names_the_stretch_rather_than_counting_to_zero() -> None:
    """`0 of 9,910 clients` reads as a failure. It is an answer, and often the
    one that was being looked for."""
    said = nobody_here(WINDOW)

    assert "No client was active" in said
    assert "01:25" in said
    assert "02:00" in said


# -- saying a stretch of time out loud -------------------------------------


def test_a_window_inside_one_day_says_the_day_once() -> None:
    assert spoken(WINDOW) == "2 May 01:25 → 02:00"


def test_a_window_across_two_days_says_both() -> None:
    across = TimeWindow(FROM, datetime(2024, 5, 3, 2, 0, tzinfo=UTC))

    assert spoken(across) == "2 May 01:25 → 3 May 02:00"


def test_an_open_end_says_which_end_is_open() -> None:
    assert spoken(TimeWindow(start=FROM)) == "2 May 01:25 onwards"
    assert spoken(TimeWindow(end=TO)) == "up to 2 May 02:00"


def test_the_whole_case_is_spoken_as_the_button_names_it() -> None:
    """All time is what the time bar calls it, so a bookmark says the same."""
    assert spoken(EVERYTHING) == "All time"


def test_an_empty_case_with_no_range_is_not_given_one() -> None:
    """A case whose every line was refused has no clients at all. There is no
    stretch to name, and "active All time" is not a sentence."""
    assert nobody_here(EVERYTHING) == "No clients in this case."
