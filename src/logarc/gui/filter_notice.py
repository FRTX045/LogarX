"""What the window says about a case that holds part of a log rather than all of it.

Wording only, with no Qt in it, so it can be read and tested without a display —
the same split `format_notice` uses.

The strip matters more than it looks. A narrowed case answers "who else was
there" with silence, and silence reads exactly like nobody: the client list, the
traffic band and every count in the panels are all true of the clients that were
kept and say nothing at all about the ones that were not. A reader who does not
know that is being misled by a case that is working correctly, which is the
failure this project treats as its worst.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from logarc.gui.quarantine_notice import Notice

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["filter_notice"]


def _named(clients: Sequence[str]) -> str:
    """The addresses, or a count once naming them all would fill the strip."""
    if len(clients) <= 3:
        return ", ".join(clients)
    return f"{', '.join(clients[:3])} and {len(clients) - 3} more"


def filter_notice(clients: Sequence[str], *, lines_filtered: int = 0) -> Notice | None:
    """What to say about a narrowed case, or nothing at all when it is whole."""
    if not clients:
        return None

    one = len(clients) == 1
    skipped = (
        f" {lines_filtered:,} lines belonging to other clients were never read."
        if lines_filtered
        else ""
    )

    return Notice(
        headline=(
            f"This case holds only {_named(clients)} — "
            f"{'that client' if one else 'those clients'}, not the whole log."
        ),
        detail=(
            "The log was narrowed at ingest, so everything here describes "
            f"{'the client that was' if one else 'the clients that were'} kept "
            f"and nothing else.{skipped}\n\n"
            "That matters most where the window looks complete: the client list "
            "holds no one else, the traffic band draws no one else, and a "
            "question about another address cannot be answered from this case "
            "at all — it needs another ingest over the same log.\n\n"
            "Nothing here is wrong. It is simply part of the story, and the "
            "part was chosen when the case was made."
        ),
        dead_files=(),
    )
