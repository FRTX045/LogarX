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
from typing import TYPE_CHECKING

from logarc.gui.density import DEFAULT as DEFAULT_DENSITY
from logarc.gui.density import Density
from logarc.gui.density import named as named_density

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "DENSITY",
    "EVERY",
    "GROUPS",
    "Setting",
    "defaults",
    "density_in",
    "in_group",
    "read",
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

    default: bool | Density
    group: str

    #: Only for a setting that is a choice rather than a switch. `None` means a
    #: checkbox; a tuple means one of these, in this order.
    choices: tuple[Density, ...] | None = None


EVERY: tuple[Setting, ...] = (
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
        key="view/traffic_band",
        label="Show the traffic band",
        note="Draw where the case's traffic sits, above the date fields.",
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

#: The one setting that is a choice rather than a switch. Named because every
#: reader of a values mapping gets `bool | Density` back and has to narrow it.
DENSITY = "view/band_density"

#: The order the dialog draws them in, read top to bottom. Graph first because
#: it holds most of them and is what a reader came here to change.
GROUPS: tuple[str, ...] = ("Graph", "Evidence", "Startup")


def in_group(group: str) -> tuple[Setting, ...]:
    """The settings filed under `group`, in catalogue order."""
    return tuple(setting for setting in EVERY if setting.group == group)


def density_in(values: dict[str, bool | Density]) -> Density:
    """How finely the band counts, as the type it is.

    Falls back rather than raising if handed something else: that is reachable
    only from a mapping built by hand, and a window refusing to draw a band
    over it would be worse than one drawing the default.
    """
    chosen = values[DENSITY]
    return chosen if isinstance(chosen, Density) else DEFAULT_DENSITY


def defaults() -> dict[str, bool | Density]:
    """What every setting starts as, before a reader has touched any of them."""
    return {setting.key: setting.default for setting in EVERY}


def read(stored: Callable[[str], object]) -> dict[str, bool | Density]:
    """What is in force, given something that hands back a stored value.

    `stored` is `QSettings.value` or anything shaped like it, so this stays
    checkable without Qt. Anything absent or unrecognised is that setting's
    default: settings outlive the code that wrote them, and a value from some
    other version of this application is not a reason to refuse to open.
    """
    values: dict[str, bool | Density] = {}
    for setting in EVERY:
        raw = stored(setting.key)
        if raw is None:
            values[setting.key] = setting.default
        elif setting.choices is not None:
            values[setting.key] = named_density(str(raw))
        else:
            values[setting.key] = _truth(raw)
    return values


def write(store: Callable[[str, object], None], values: dict[str, bool | Density]) -> None:
    """Put `values` where `read` will find them again.

    The round trip is the point. Written in a form the store cannot hand back,
    a preference is lost the next time the window opens — and lost quietly,
    because a value that cannot be read looks exactly like one never set.
    """
    for setting in EVERY:
        value = values[setting.key]
        store(setting.key, value.name.lower() if isinstance(value, Density) else bool(value))


def _truth(raw: object) -> bool:
    """A remembered yes or no, normalised rather than trusted.

    Both stores hand these back as text: the registry keeps `REG_SZ "false"`,
    which is a non-empty string and therefore true to Python. Trusted, every
    switch a reader turned off would come back on at the next launch.
    """
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in {"false", "0", ""}
