"""A slice of time, and the name it gives whatever is reconstructed inside it.

No Qt, no disk. Everything here is a decision about what a range means, and the
one that matters most is at the bottom: an open range has to leave every
identifier exactly as it was, or every case and report already on disk stops
matching the tool that made it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from logarx.core.window import EVERYTHING, TimeWindow

MORNING = datetime(2024, 5, 2, 1, 25, 30, tzinfo=UTC)
NOON = datetime(2024, 5, 2, 2, 57, 0, tzinfo=UTC)


# -- what a range holds ----------------------------------------------------


def test_an_open_range_holds_everything() -> None:
    assert EVERYTHING.is_open
    assert EVERYTHING.contains(MORNING)
    assert EVERYTHING.contains(datetime(1999, 1, 1, tzinfo=UTC))


def test_a_range_with_ends_is_not_open() -> None:
    assert not TimeWindow(MORNING, NOON).is_open


def test_both_ends_are_inside_the_range() -> None:
    """Inclusive, because a range typed as 01:25:30 to 02:57:00 reads as
    covering both of those seconds, and a reader who names the second an attack
    started should not have to add one to see it."""
    window = TimeWindow(MORNING, NOON)

    assert window.contains(MORNING)
    assert window.contains(NOON)


def test_outside_is_outside() -> None:
    window = TimeWindow(MORNING, NOON)

    assert not window.contains(MORNING.replace(second=29))
    assert not window.contains(NOON.replace(second=1))


def test_a_range_with_only_a_start_means_ever_since() -> None:
    window = TimeWindow(start=MORNING)

    assert window.contains(NOON)
    assert not window.contains(MORNING.replace(second=29))


def test_a_range_with_only_an_end_means_up_until() -> None:
    window = TimeWindow(end=NOON)

    assert window.contains(MORNING)
    assert not window.contains(NOON.replace(second=1))


def test_a_range_that_ends_before_it_starts_is_refused() -> None:
    """Not swapped quietly. The fields in the window stop it happening, so a
    reversed pair arriving here means something else is already wrong, and
    swapping would hide that instead of reporting it."""
    with pytest.raises(ValueError, match="ends before"):
        TimeWindow(NOON, MORNING)


def test_a_range_of_one_instant_is_allowed() -> None:
    window = TimeWindow(MORNING, MORNING)

    assert window.contains(MORNING)
    assert not window.contains(MORNING.replace(second=31))


# -- the name a range gives what is reconstructed inside it ----------------


def test_an_open_range_names_nothing() -> None:
    """The contract that keeps every case and report already on disk valid: with
    no range, identifiers are exactly what they always were."""
    assert EVERYTHING.tag == ""


def test_a_full_range_spells_both_ends() -> None:
    assert TimeWindow(MORNING, NOON).tag == "20240502T012530-20240502T025700"


def test_an_open_end_leaves_its_side_blank() -> None:
    assert TimeWindow(start=MORNING).tag == "20240502T012530-"
    assert TimeWindow(end=NOON).tag == "-20240502T025700"


@pytest.mark.parametrize(
    "window",
    [
        EVERYTHING,
        TimeWindow(MORNING, NOON),
        TimeWindow(start=MORNING),
        TimeWindow(end=NOON),
    ],
    ids=["open", "both", "from", "until"],
)
def test_a_tag_reads_back_as_the_range_that_wrote_it(window: TimeWindow) -> None:
    """An identifier carries the range that produced it, so the range has to be
    recoverable from it — otherwise the identifier says which report it belongs
    to without saying what that report covers."""
    assert TimeWindow.from_tag(window.tag) == window


def test_a_second_apart_is_a_different_name() -> None:
    """Seconds are always written. Truncated to minutes, two ranges that differ
    by a second would produce identical identifiers for different content —
    which is the failure this whole scheme exists to prevent."""
    close = TimeWindow(MORNING, NOON.replace(second=1))

    assert TimeWindow(MORNING, NOON).tag != close.tag


@pytest.mark.parametrize(
    "text", ["nonsense", "20240502T012530", "-", "x-y", "20240502T012530-nonsense"], ids=repr
)
def test_a_tag_nobody_can_read_is_an_error(text: str) -> None:
    """Loud, not quiet. This string arrives as part of something claiming to be
    evidence; a range guessed from a name that could not be parsed would put a
    wrong window on a real finding."""
    with pytest.raises(ValueError, match="range"):
        TimeWindow.from_tag(text)


# -- holding a range inside the case it belongs to ------------------------


def test_clamping_trims_an_end_that_reaches_past_the_case() -> None:
    window = TimeWindow(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))

    assert window.clamped_to(MORNING, NOON) == TimeWindow(MORNING, NOON)


def test_clamping_leaves_a_range_already_inside_alone() -> None:
    window = TimeWindow(MORNING, NOON)

    assert window.clamped_to(
        datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC)
    ) == (window)


def test_clamping_an_open_range_gives_the_whole_case() -> None:
    assert EVERYTHING.clamped_to(MORNING, NOON) == TimeWindow(MORNING, NOON)
