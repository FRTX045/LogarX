"""What the window says when a case does not hold everything its logs did.

Free of Qt, because this is the judgement that can misinform rather than the
drawing of it. `ingest/quarantine.py` opens by calling a silently incomplete
result this tool's worst failure mode — and then only the CLI was ever told.

Two decisions live here.

**Whether to speak at all.** A clean ingest gets silence, matching `Quarantine`
itself, which creates no file when there is nothing to put in it so that no
empty artefact is mistaken for a problem. A strip permanently reporting "0
lines failed" would be exactly that artefact, in the hardest place to ignore.

**How loudly.** Some lines failing is damage inside a log, and a strip is the
right weight for it. A file that produced *no events at all* is a different
thing: nothing from it is in the case, which is what the wrong parser looks
like, and the reader has to re-ingest rather than go and read a few bad lines.
That earns an interruption.

The dead-file test is **per source file**. Judged per case — quarantined equal
to lines read — it is only true when every file failed, so ingesting four good
logs and one syslog would stay quiet while a whole file contributed nothing.
Per file also covers the every-file case, so there is one rule instead of two.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from logarc.style import plural

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.storage.case import SourceRecord

__all__ = ["Notice", "notice_for"]


@dataclass(frozen=True, slots=True)
class Notice:
    """What the window should say. `None` in its place means say nothing."""

    headline: str
    detail: str
    dead_files: tuple[str, ...]
    """Files that produced no events at all. Empty in the ordinary damaged case."""

    @property
    def is_blocking(self) -> bool:
        """Whether this warrants interrupting rather than only a strip."""
        return bool(self.dead_files)


def _share(part: int, whole: int) -> str:
    """`part` of `whole` as a percentage, refusing to round down to nothing.

    Three lines in five million is 0.00006%, and one decimal place renders that
    as "0.0%" — a figure saying nothing failed, in the same sentence as a
    headline saying three did. A reader believes the number over the noun.
    """
    percent = part * 100 / whole
    return "under 0.1%" if percent < 0.1 else f"{percent:.1f}%"


def _dead_file_detail(dead: Sequence[SourceRecord]) -> str:
    """Name the format each dead file was read as — the actual diagnosis.

    A count says a file failed. The format says *why*, and separates the two
    explanations a reader would otherwise have to guess between: the wrong
    parser, or a log that genuinely holds nothing.
    """
    if len(dead) == 1:
        only = dead[0]
        opening = (
            f"{only.file_id} was read as {only.log_format}, and not one of its "
            f"{only.lines_read:,} lines parsed. Nothing from it is in this case."
        )
    else:
        named = ", ".join(
            f"{record.file_id} ({record.lines_read:,} lines, read as {record.log_format})"
            for record in dead
        )
        opening = (
            f"{len(dead)} logs produced no events at all: {named}. "
            "Nothing from them is in this case."
        )

    return (
        f"{opening}\n\n"
        "Every line being refused is what reading a log with the wrong format looks "
        "like. Make the case again from Case → New from logs… and choose the "
        "format there."
    )


def notice_for(sources: Sequence[SourceRecord]) -> Notice | None:
    """What to say about `sources`, or nothing at all.

    Blank lines count toward `lines_read` because the file contains them, so
    the wording says lines *read into this case* rather than "the log" — a
    reader dividing the two printed numbers has to arrive at the printed share.
    """
    quarantined = sum(record.lines_quarantined for record in sources)
    if quarantined <= 0:
        # Covers the clean case, the empty case, and a file of only blank
        # lines: nothing was refused, so there is no parser fault to report.
        return None

    lines_read = sum(record.lines_read for record in sources)
    dead = [
        record for record in sources if record.events_parsed == 0 and record.lines_quarantined > 0
    ]

    if dead:
        return Notice(
            headline=(
                f"{dead[0].file_id} could not be read"
                if len(dead) == 1
                else f"{len(dead)} of this case's logs could not be read"
            ),
            detail=_dead_file_detail(dead),
            dead_files=tuple(record.file_id for record in dead),
        )

    return Notice(
        headline=f"{plural(quarantined, 'line')} could not be parsed",
        detail=(
            f"{_share(quarantined, lines_read)} of the {lines_read:,} lines read into "
            "this case never became events, so it does not hold everything its logs "
            "do. Each one was kept, with the reason it was refused."
        ),
        dead_files=(),
    )
