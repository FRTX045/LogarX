"""What the reader can change, and what it is set to before they change it.

The catalogue, not the dialog. Free of Qt, because the judgements here — which
settings exist, what each is called, and what it starts as — are the ones worth
checking without a display, and the ones a second copy of this list would get
quietly wrong.
"""

from __future__ import annotations

import pytest

from logarc.gui import prefs
from logarc.gui.density import Density


def test_every_setting_the_window_keeps_is_in_the_catalogue() -> None:
    """The keys are the ones already on readers' machines. A catalogue that
    renamed one would hand back a default and lose their preference without
    saying so."""
    assert {setting.key for setting in prefs.EVERY} == {
        "view/wrap_traces",
        "view/session_boxes",
        "view/traffic_band",
        "view/ask_unsaved_arrangement",
        "view/band_density",
        "view/decode_targets",
        "analysis/run_crs",
        "cases/reopen_last",
    }


def test_the_defaults_are_the_ones_the_menu_already_used() -> None:
    """Moving a setting into a dialog must not change what it starts as. Read
    off the menu entries these replace."""
    assert prefs.defaults() == {
        "view/wrap_traces": True,
        "view/session_boxes": True,
        "view/traffic_band": True,
        "view/ask_unsaved_arrangement": True,
        "view/band_density": Density.FINE,
        "view/decode_targets": True,
        "analysis/run_crs": True,
        "cases/reopen_last": False,
    }


def test_every_setting_says_what_it_is_for() -> None:
    """The label alone is not enough: `Wrap long traces` does not say what a
    trace is or why it would be wrapped. The menu carried a sentence for each
    of these in its status tips, and the dialog is where that sentence goes
    now — losing it in the move would be the move making things worse."""
    for setting in prefs.EVERY:
        assert setting.label, f"{setting.key} has no label"
        assert len(setting.note) > 20, f"{setting.key} explains nothing: {setting.note!r}"
        assert setting.note.endswith("."), f"{setting.key} is not a sentence"


def test_the_groups_hold_every_setting_between_them() -> None:
    """A setting in no group is a setting the dialog never draws — it would be
    reachable only by editing the settings file by hand."""
    grouped = [setting for group in prefs.GROUPS for setting in prefs.in_group(group)]

    assert sorted(s.key for s in grouped) == sorted(s.key for s in prefs.EVERY)


def test_the_groups_come_back_in_a_settled_order() -> None:
    """The dialog is read top to bottom and remembered by position."""
    assert prefs.GROUPS == ("Graph", "Evidence", "Analysis", "Startup")


def test_a_group_keeps_its_settings_in_catalogue_order() -> None:
    assert [s.key for s in prefs.in_group("Graph")] == [
        "view/wrap_traces",
        "view/session_boxes",
        "view/traffic_band",
        "view/ask_unsaved_arrangement",
        "view/band_density",
    ]


def test_the_startup_setting_is_not_filed_under_the_graph() -> None:
    """It was in the View menu, where it decided nothing about the view. What
    it decides is what happens when the application opens."""
    startup = [s.key for s in prefs.in_group("Startup")]

    assert startup == ["cases/reopen_last"]


def test_crs_is_on_until_the_reader_turns_it_off() -> None:
    """The decision this setting records, made 2026-10-05: CRS runs after every
    scan, and the reader who does not want it says so once, here."""
    (setting,) = prefs.in_group("Analysis")

    assert setting.key == prefs.RUN_CRS
    assert setting.default is True


def test_the_crs_setting_names_what_it_costs() -> None:
    """It runs after every scan, so the note says that it adds time. No figure:
    a number in a dialog gets no footnote, which is how two wrong ones reached
    the offer this setting replaces."""
    (setting,) = prefs.in_group("Analysis")

    assert "longer" in setting.note
    assert not any(char.isdigit() for char in setting.note)


def test_the_catalogue_answers_which_counting_is_in_force() -> None:
    """The mapping holds switches and one choice together, so everything that
    reads it gets `bool | Density` back and has to narrow it. Named once here
    rather than asserted at each of the places that needs it."""
    assert prefs.density_in({**prefs.defaults(), "view/band_density": Density.COARSE}) is (
        Density.COARSE
    )


def test_a_counting_that_is_not_one_falls_back_rather_than_raising() -> None:
    """Reached only if a caller hands over something built by hand. A window
    that refused to draw a band over it would be worse than one that draws the
    default."""
    assert (
        prefs.density_in({**prefs.defaults(), "view/band_density": True})
        is (prefs.defaults()["view/band_density"])
    )


# -- reading and writing them ---------------------------------------------


def test_stored_text_comes_back_as_the_value_it_stands_for() -> None:
    """Both stores hand these back as text — the registry keeps `REG_SZ
    "false"`, which is a non-empty string and therefore true."""
    stored = {
        "view/wrap_traces": "false",
        "view/traffic_band": "true",
        "view/band_density": "coarse",
        "view/decode_targets": "true",
        "cases/reopen_last": "false",
    }

    read = prefs.read(stored.get)

    assert read["view/wrap_traces"] is False
    assert read["view/traffic_band"] is True
    assert read["view/band_density"] is Density.COARSE
    assert read["cases/reopen_last"] is False


def test_anything_unset_falls_back_to_its_default() -> None:
    assert prefs.read(lambda key: None) == prefs.defaults()


def test_a_value_from_some_other_version_falls_back_too() -> None:
    """Settings outlive the code that wrote them, and a name this build does
    not know is not a reason to refuse to open."""
    read = prefs.read({"view/band_density": "luxuriant"}.get)

    assert read["view/band_density"] is prefs.defaults()["view/band_density"]


def test_writing_puts_back_what_reading_would_return() -> None:
    """The round trip. Written in a form the store cannot read back, a
    preference is lost the next time the window opens — silently, because a
    missing value reads as its default."""
    written: dict[str, object] = {}

    prefs.write(written.__setitem__, {**prefs.defaults(), "view/band_density": Density.COARSE})

    assert prefs.read(written.get) == {**prefs.defaults(), "view/band_density": Density.COARSE}


@pytest.mark.parametrize("key", ["view/wrap_traces", "cases/reopen_last"])
def test_a_switch_is_written_as_something_that_reads_back(key: str) -> None:
    written: dict[str, object] = {}

    prefs.write(written.__setitem__, {**prefs.defaults(), key: False})

    assert prefs.read(written.get)[key] is False


# -- the answer the CRS offer remembered, before this was a setting ----------


def test_a_reader_who_told_the_old_offer_never_is_still_not_asked_to_wait() -> None:
    """**The one migration here.** Before CRS ran by itself, a dialog asked after
    every scan and a ticked box stored the answer under `crs/after-ingest`.
    Somebody who chose "never" there chose it on purpose, and turning CRS on
    underneath them because the question went away would be overriding them."""
    read = prefs.read({"crs/after-ingest": "never"}.get)

    assert read[prefs.RUN_CRS] is False


@pytest.mark.parametrize("answered", ["always", "quiet", ""])
def test_every_other_old_answer_leaves_it_on(answered: str) -> None:
    """An old "always" is what it now does anyway, and "quiet" was never about
    running CRS — it silenced the notice that the sidecar is missing."""
    read = prefs.read({"crs/after-ingest": answered}.get)

    assert read[prefs.RUN_CRS] is True


def test_the_setting_itself_outranks_the_old_answer() -> None:
    """Once the reader has used the dialog, what they set there is the answer.
    The old key is never deleted, so without this a "never" from last year
    would win against a box ticked this morning."""
    stored = {"crs/after-ingest": "never", prefs.RUN_CRS: "true"}

    assert prefs.read(stored.get)[prefs.RUN_CRS] is True
