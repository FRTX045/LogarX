"""What the reader can change about how the window behaves.

One catalogue, read by the dialog that draws these and by the window that
applies them. Written twice they would disagree about a default eventually, and
the disagreement would be invisible: a window that starts one way and a dialog
that claims it starts another.

Free of Qt, because what belongs here are judgements rather than widgets —
which settings exist, what each is called, what it starts as, and which of them
belong together. The dialog is `gui.preferences`; it draws whatever this says.

The keys are the ones already on readers' machines, unchanged by the move out
of the View menu. A renamed key is a preference silently lost: the old value
stays in the store, unread, and the window quietly falls back to the default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.gui.density import DEFAULT as DEFAULT_DENSITY
from logarc.gui.density import Density
from logarc.gui.density import named as named_density
from logarc.gui.folding import DEFAULT_FOLD, FoldRule
from logarc.gui.folding import named as named_fold
from logarc.gui.text_size import TextSize
from logarc.gui.text_size import named as named_text_size

if TYPE_CHECKING:
    from collections.abc import Callable

#: Every kind of value the catalogue holds: a switch or a named choice.
Value = bool | Density | FoldRule | TextSize

TEXT_SIZE: Final = "view/text_size"

#: Whether, and how, the evidence panel folds lines that repeat. Named because
#: the window reads it on every start and every visit to Preferences.
FOLD: Final = "view/fold_lines"

#: The switch that decides whether leaving an unsaved arrangement warns first.
#: Named here rather than spelled out at each use: the dialog writes it, the
#: window reads it, and the keeper acts on it, and three copies of a settings
#: key is three chances for one of them to be silently reading nothing.
ASK_UNSAVED_ARRANGEMENT: Final = "view/ask_unsaved_arrangement"

#: Whether CRS runs by itself once a scan finishes. Named for the same reason:
#: the window reads it at the end of every ingest.
RUN_CRS: Final = "analysis/run_crs"

#: Where the dialog this setting replaced kept its answer. Read once, for the
#: reader who told it "never" — see `read`.
_ANSWERED_BEFORE: Final = "crs/after-ingest"

__all__ = [
    "ASK_UNSAVED_ARRANGEMENT",
    "DENSITY",
    "EVERY",
    "FOLD",
    "GROUPS",
    "RUN_CRS",
    "TEXT_SIZE",
    "Setting",
    "Value",
    "defaults",
    "density_in",
    "fold_rule_in",
    "in_group",
    "read",
    "text_size_in",
    "write",
]


@dataclass(frozen=True, slots=True)
class Setting:
    """One preference: where it is kept, what it is called, what it means."""

    key: str
    label: str
    note: str
    """A sentence saying what it is for. The menu carried one of these for each
    of these settings as a status tip; the dialog is where it goes now, and
    losing it in the move would make the move a step backwards."""

    default: Value
    group: str

    #: Only for a setting that is a choice rather than a switch. `None` means a
    #: checkbox; a tuple means one of these, in this order. Each choice has a
    #: `label` for the dialog and a `stored` form for the settings file.
    choices: tuple[Density, ...] | tuple[FoldRule, ...] | tuple[TextSize, ...] | None = None


EVERY: tuple[Setting, ...] = (
    Setting(
        key=TEXT_SIZE,
        label="Text size (restart required)",
        note=(
            "Automatic fits the available desktop space and keeps larger system text. "
            "Choose a fixed size to override it on this laptop. Applies after restarting logarc."
        ),
        default=TextSize.AUTOMATIC,
        group="Appearance",
        choices=tuple(TextSize),
    ),
    Setting(
        key="view/wrap_traces",
        label="Wrap long traces",
        note=(
            "Fold a long session onto further rows so the captions stay readable, "
            "instead of keeping it straight and scrolling."
        ),
        default=True,
        group="Graph",
    ),
    Setting(
        key="view/session_boxes",
        label="Outline each session",
        note=(
            "Draw a box around each visit on the trace, with its number, how many "
            "activities it holds and when it ran."
        ),
        default=True,
        group="Graph",
    ),
    Setting(
        key="view/traffic_band",
        label="Show timeline",
        note="Show the traffic timeline above the date fields; also available under View.",
        default=True,
        group="Graph",
    ),
    Setting(
        key=ASK_UNSAVED_ARRANGEMENT,
        label="Ask before leaving an unsaved arrangement",
        note=(
            "Warn when leaving a client whose activities you have moved and not "
            "saved, rather than putting them back without saying so."
        ),
        default=True,
        group="Graph",
    ),
    Setting(
        key="view/band_density",
        label="Band detail",
        note=(
            "How finely that traffic is counted. Finer is not slower: measured on "
            "two million events, the coarsest and the finest are 70ms apart."
        ),
        default=DEFAULT_DENSITY,
        group="Graph",
        choices=(Density.COARSE, Density.MEDIUM, Density.FINE),
    ),
    Setting(
        key="view/decode_targets",
        label="Decode URL escapes",
        note=(
            "Show request targets as the attacker wrote them — %27+OR+%271%27%3D%271 "
            "reads as ' OR '1'='1 — rather than exactly as the log holds them."
        ),
        default=True,
        group="Evidence",
    ),
    Setting(
        key=FOLD,
        label="Fold repeated lines",
        note=(
            "Show lines next to each other that match as one row with a count; open the "
            "row to see each line. The default folds only lines with the same request, "
            "status and size, so a row never shows a value one of its lines did not have. "
            "The others fold more, and mark the values that differ as mixed."
        ),
        default=DEFAULT_FOLD,
        group="Evidence",
        choices=tuple(FoldRule),
    ),
    Setting(
        key=RUN_CRS,
        label="Run OWASP CRS after a scan",
        note=(
            "Replay every new case through CRS, the ruleset most web application "
            "firewalls use. It catches attacks logarc's own rules miss, and makes "
            "each scan take longer; the card it shows can stop it and keeps what "
            "it found."
        ),
        default=True,
        group="Analysis",
    ),
    Setting(
        key="cases/reopen_last",
        label="Reopen the last case on start",
        note=(
            "Open the case you were last working on as soon as the window appears, "
            "rather than starting with the list of recent cases."
        ),
        default=False,
        group="Startup",
    ),
)

#: The band's choice. Named because every reader of a values mapping gets a
#: `Value` back and has to narrow it; `FOLD` above is named for the same reason.
DENSITY = "view/band_density"

#: The order the dialog draws them in, read top to bottom.
GROUPS: tuple[str, ...] = ("Appearance", "Graph", "Evidence", "Analysis", "Startup")


def in_group(group: str) -> tuple[Setting, ...]:
    """The settings filed under `group`, in catalogue order."""
    return tuple(setting for setting in EVERY if setting.group == group)


def density_in(values: dict[str, Value]) -> Density:
    """How finely the band counts, as the type it is.

    Falls back rather than raising if handed something else: that is reachable
    only from a mapping built by hand, and a window refusing to draw a band
    over it would be worse than one drawing the default.
    """
    chosen = values[DENSITY]
    return chosen if isinstance(chosen, Density) else DEFAULT_DENSITY


def fold_rule_in(values: dict[str, Value]) -> FoldRule:
    """How the evidence panel folds, as the type it is; the default if handed anything else."""
    chosen = values[FOLD]
    return chosen if isinstance(chosen, FoldRule) else DEFAULT_FOLD


def defaults() -> dict[str, Value]:
    """What every setting starts as, before a reader has touched any of them."""
    return {setting.key: setting.default for setting in EVERY}


def text_size_in(values: dict[str, Value]) -> TextSize:
    """The selected text size, with automatic as the fallback."""
    chosen = values[TEXT_SIZE]
    return chosen if isinstance(chosen, TextSize) else TextSize.AUTOMATIC


def read(stored: Callable[[str], object]) -> dict[str, Value]:
    """What is in force, given something that hands back a stored value.

    `stored` is `QSettings.value` or anything shaped like it, so this stays
    checkable without Qt. Anything absent or unrecognised is that setting's
    default: settings outlive the code that wrote them, and a value from some
    other version of this application is not a reason to refuse to open.
    """
    values: dict[str, Value] = {}
    for setting in EVERY:
        raw = stored(setting.key)
        if raw is None and setting.key == RUN_CRS and stored(_ANSWERED_BEFORE) == "never":
            # Before CRS ran by itself, a dialog asked after every scan and a
            # ticked box kept the answer. "never" was chosen on purpose, and the
            # question going away is not the reader changing their mind.
            raw = False
        if raw is None:
            values[setting.key] = setting.default
        elif isinstance(setting.default, TextSize):
            values[setting.key] = named_text_size(str(raw))
        elif isinstance(setting.default, FoldRule):
            values[setting.key] = named_fold(str(raw))
        elif setting.choices is not None:
            values[setting.key] = named_density(str(raw))
        else:
            values[setting.key] = _truth(raw)
    return values


def write(store: Callable[[str, object], None], values: dict[str, Value]) -> None:
    """Put `values` where `read` will find them again.

    The round trip is the point. Written in a form the store cannot hand back,
    a preference is lost the next time the window opens — and lost quietly,
    because a value that cannot be read looks exactly like one never set.
    """
    for setting in EVERY:
        value = values[setting.key]
        store(
            setting.key,
            value.stored if isinstance(value, Density | FoldRule | TextSize) else bool(value),
        )


def _truth(raw: object) -> bool:
    """A remembered yes or no, normalised rather than trusted.

    Both stores hand these back as text: the registry keeps `REG_SZ "false"`,
    which is a non-empty string and therefore true to Python. Trusted, every
    switch a reader turned off would come back on at the next launch.
    """
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in {"false", "0", ""}
