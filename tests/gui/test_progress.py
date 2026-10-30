"""What a long ingest is allowed to claim about itself.

Qt-free, like the other seams: an estimate is a judgement, and it is the one
here that can misinform. No display is needed to check any of it.
"""

from __future__ import annotations

from typing import Any

from zodiarc.gui.progress import SETTLE_SECONDS, Progress, Reading


def reading(**over: Any) -> Progress:
    fields: dict[str, Any] = {
        "file_name": "access.log",
        "file_index": 1,
        "file_count": 1,
        "lines": 1_482_119,
        "bytes_done": 1_432_000_000,
        "bytes_total": 2_310_000_000,
        "seconds": 30.0,
    }
    fields.update(over)
    return Progress(**fields)


def test_the_fraction_is_bytes_read_over_bytes_there_are() -> None:
    assert reading().fraction == 1_432_000_000 / 2_310_000_000
    assert reading().percent == "62%"


def test_a_log_of_unknown_size_has_no_fraction() -> None:
    """Rather than a zero, which draws an empty bar that never moves and reads
    as a stalled ingest."""
    assert reading(bytes_total=0).fraction is None
    assert reading(bytes_total=0).percent is None


def test_a_finished_read_does_not_exceed_itself() -> None:
    """A batch can carry the read past the size the file reported: the last one
    overshoots, and a compressed stream's accounting is not exact either. A bar
    at 104% says the tool cannot count."""
    assert reading(bytes_done=2_400_000_000).fraction == 1.0
    assert reading(bytes_done=2_400_000_000).percent == "100%"


def test_the_rate_is_what_has_already_happened() -> None:
    assert reading(lines=600_000, seconds=10.0).rate == "60,000 lines/s"


def test_there_is_no_rate_before_any_time_has_passed() -> None:
    assert reading(seconds=0.0).rate is None


def test_no_estimate_until_the_read_has_settled() -> None:
    """The first seconds are the least representative: the cache is cold and
    the format has only just been sniffed. An estimate drawn from them is a
    number that looks like a result and is not."""
    assert reading(seconds=SETTLE_SECONDS - 0.1).remaining is None
    assert reading(seconds=SETTLE_SECONDS + 0.1).remaining is not None


def test_the_estimate_says_it_is_one() -> None:
    # 1.432 GB in 30s is 47.7 MB/s, and 878 MB is left.
    assert reading().remaining == "about 18s"


def test_a_long_estimate_is_given_in_minutes() -> None:
    assert reading(bytes_done=100_000_000, seconds=60.0).remaining == "about 22m 6s"


def test_an_unmeasurable_read_offers_no_estimate() -> None:
    assert reading(bytes_total=0).remaining is None
    assert reading(bytes_done=0).remaining is None


def test_a_finished_read_offers_no_estimate() -> None:
    """Nothing left to wait for. "about 0s" beside a full bar is noise."""
    assert reading(bytes_done=2_310_000_000).remaining is None


def test_one_file_is_named_without_a_count() -> None:
    """ "access.log (1 of 1)" is a count that can only ever say one thing."""
    assert reading().subject == "access.log"


def test_several_files_say_which_one_this_is() -> None:
    assert reading(file_index=2, file_count=3).subject == "access.log (2 of 3)"


# -- carrying the counts across files ---------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_a_reading_names_the_file_it_is_on() -> None:
    clock = FakeClock()
    reading_of = Reading(["a.log", "b.log"], [1_000, 3_000], clock=clock)

    clock.now = 1.0
    first = reading_of.advance(lines=100, bytes_read=500)

    assert first.subject == "a.log (1 of 2)"
    assert first.bytes_total == 4_000


def test_the_counts_carry_across_a_file_boundary() -> None:
    """`Case.ingest` restarts its counts at every log. A reader watching this
    would see the numbers fall back to nothing part-way through and read it as
    an ingest starting over — so what is finished has to be carried."""
    clock = FakeClock()
    reading_of = Reading(["a.log", "b.log"], [1_000, 3_000], clock=clock)

    clock.now = 1.0
    reading_of.advance(lines=400, bytes_read=1_000)
    reading_of.next_file()
    clock.now = 2.0
    second = reading_of.advance(lines=50, bytes_read=200)

    assert second.lines == 450, "the first file's 400 lines did not vanish"
    assert second.bytes_done == 1_200
    assert second.subject == "b.log (2 of 2)"


def test_a_boundary_credits_the_whole_file_not_the_last_report() -> None:
    """The final batch of a file reports fewer bytes than the file holds — the
    reader stops at the last line, and a compressed stream's count is its own.
    Crediting the last report would leave a shortfall on every boundary, and a
    ten-file ingest would finish reading well short of 100%."""
    clock = FakeClock()
    reading_of = Reading(["a.log", "b.log"], [1_000, 1_000], clock=clock)

    clock.now = 1.0
    reading_of.advance(lines=400, bytes_read=940)
    reading_of.next_file()
    clock.now = 2.0
    second = reading_of.advance(lines=400, bytes_read=1_000)

    assert second.bytes_done == 2_000, "the whole of a.log counts once it is done"
    assert second.fraction == 1.0


def test_the_elapsed_time_is_the_whole_read() -> None:
    clock = FakeClock()
    reading_of = Reading(["a.log"], [1_000], clock=clock)

    clock.now = 12.5
    assert reading_of.advance(lines=1, bytes_read=1).seconds == 12.5


def test_a_reading_of_one_file_does_not_count_them() -> None:
    clock = FakeClock()
    reading_of = Reading(["a.log"], [1_000], clock=clock)

    clock.now = 1.0
    assert reading_of.advance(lines=1, bytes_read=1).subject == "a.log"
