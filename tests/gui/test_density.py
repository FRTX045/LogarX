"""How many buckets the band asks for.

Arithmetic, so no display and no Qt. The judgement it holds — that a bucket
finer than a pixel cannot be drawn, and that a band nobody has laid out yet
must still ask for something usable — is the kind that is easy to get wrong
once and never notice, which is why it lives somewhere it can be checked.
"""

from __future__ import annotations

import pytest

from logarc.gui.density import DEFAULT, Density, buckets_for, named


def test_a_wider_band_asks_for_more_buckets() -> None:
    """The point of the whole module. A fixed count knows nothing about the
    band it is drawn into: 200 buckets is a reasonable histogram at 900px and
    a row of hairlines at 600."""
    assert buckets_for(1200, Density.MEDIUM) > buckets_for(600, Density.MEDIUM)


def test_a_finer_setting_asks_for_more_than_a_coarser_one() -> None:
    wide = 900
    assert (
        buckets_for(wide, Density.FINE)
        > buckets_for(wide, Density.MEDIUM)
        > buckets_for(wide, Density.COARSE)
    )


def test_the_finest_setting_is_one_bucket_to_a_pixel() -> None:
    """The end of the scale, and the reason there is no finer one: two buckets
    sharing a pixel draw as one bar, so the extra one is a row in a result the
    reader can never see."""
    assert buckets_for(900, Density.FINE) == 900


def test_no_setting_ever_asks_for_more_buckets_than_the_band_has_pixels() -> None:
    for density in Density:
        assert buckets_for(700, density) <= 700


def test_a_band_that_has_not_been_laid_out_yet_still_asks_for_something() -> None:
    """A case can be opened before the window has settled, and Qt reports a
    width of zero until it has. Divided down from that, the first band of every
    session would be drawn from no buckets at all."""
    assert buckets_for(0, Density.MEDIUM) >= 20


def test_a_remembered_name_comes_back_as_the_setting_it_names() -> None:
    for density in Density:
        assert named(density.name.lower()) is density


def test_a_name_from_some_other_version_falls_back_to_the_default() -> None:
    """Settings outlive the code that wrote them. A value this build does not
    recognise is not a reason to refuse to draw a band."""
    assert named("luxuriant") is DEFAULT
    assert named("") is DEFAULT


@pytest.mark.parametrize("width", [1, 7, 13, 599, 601, 2560])
def test_every_width_produces_a_usable_count(width: int) -> None:
    """Including the awkward ones. An integer division that lands on zero is a
    band with nothing in it, and a caller has no way to tell that from a case
    with no traffic."""
    for density in Density:
        assert buckets_for(width, density) >= 1
