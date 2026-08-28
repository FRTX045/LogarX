"""What the window says when a case's log format has been edited since.

Free of Qt, for the same reason `gui.quarantine_notice` beside it is: this is
the judgement that can mislead, and only the drawing of it needs a display.

The risk this wording exists to manage is specific. Any strip above a case
reads as "something is wrong with your case", and here nothing is: the case
keeps its own copy of the definition and reads back exactly as it was ingested.
So the reassurance goes first, before the difference is described. A notice
that leads with the change would send an investigator to re-ingest evidence
that was never in doubt.

It reuses `Notice` rather than defining a near-identical twin. The two notices
are about different things, but the shape the strip renders is the same one,
and `is_blocking` is already false for anything with no dead files — which is
correct here, permanently: an intact case is not worth interrupting for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from logarc.gui.quarantine_notice import Notice
from logarc.gui.style import plural

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.formats import FormatDrift

__all__ = ["drift_notice"]


def _headline(drifts: Sequence[FormatDrift]) -> str:
    if len(drifts) == 1:
        return f"The format {drifts[0].name} has changed since this case was made"
    names = sorted({drift.name for drift in drifts})
    if len(names) == 1:
        return f"The format {names[0]} has changed since these {len(drifts)} logs were read"
    return f"{plural(len(drifts), 'log')} were read with formats that have changed since"


def _comparison(drifts: Sequence[FormatDrift]) -> str:
    """Both definitions, per format that moved.

    Shown rather than merely reported as "different", because a reader told
    only that something changed has to go and compare two strings by hand — and
    the whole reason to mention it is that the difference is what explains why
    a re-ingest today would not produce this case.
    """
    lines = []
    for name in sorted({drift.name for drift in drifts}):
        drift = next(item for item in drifts if item.name == name)
        lines.append(
            f"{name}\n    read with:  {drift.stored.summary}\n    now saved:  {drift.current.summary}"
        )
    return "\n".join(lines)


def drift_notice(drifts: Sequence[FormatDrift]) -> Notice | None:
    """What to say about `drifts`, or nothing at all when there are none."""
    if not drifts:
        return None

    return Notice(
        headline=_headline(drifts),
        detail=(
            "This case still reads exactly as it was ingested, from its own copy of "
            "the format — nothing here needs re-ingesting.\n\n"
            "What changed is the saved format of that name, so ingesting the same "
            f"log today would not produce this case:\n\n{_comparison(drifts)}"
        ),
        dead_files=(),
    )
