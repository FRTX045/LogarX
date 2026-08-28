"""Where a user's saved formats meet the cases that were read with them.

`parsers.library` knows about saved formats and nothing about cases;
`storage.case` knows about cases and nothing about the library. This is the one
place that holds both, which is why it sits at the top level beside `case.py`
and `evidence.py` rather than inside either package.

Only the interface layers use it. The engine reads a case from the definition
the case itself stored and never consults the library at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from logarc.parsers.library import load_library
from logarc.parsers.spec import FormatSpecError, spec_from_dict

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.parsers.spec import FormatSpec
    from logarc.storage.case import SourceRecord

__all__ = ["FormatDrift", "drifted_sources"]


@dataclass(frozen=True, slots=True)
class FormatDrift:
    """One ingested file whose format has been edited since it was read."""

    file_id: str
    name: str
    stored: FormatSpec
    """What the case was actually read with, and still reads with."""

    current: FormatSpec
    """What that name means today."""


def drifted_sources(
    sources: Sequence[SourceRecord], library: Sequence[FormatSpec] | None = None
) -> list[FormatDrift]:
    """The sources read with a format whose saved definition has since changed.

    The case is not affected — it carries its own copy and reads back exactly as
    ingested. This exists so the investigator is told, rather than assuming the
    format they can see today is the one that produced what they are looking at.

    Three things are deliberately *not* reported, because in each of them
    nothing can honestly be said:

    * a format that is no longer saved at all — there is nothing to compare
      against, and the case still reads correctly, so a warning here would only
      teach the user to dismiss warnings;
    * a source recorded before definitions were stored, which has a name and no
      copy;
    * a stored definition this logarc cannot read, which was written by a newer
      one.

    `library` defaults to whatever the user has saved right now, which is how
    the CLI and the GUI call it.
    """
    saved = {spec.name: spec for spec in (load_library() if library is None else library)}

    drifts: list[FormatDrift] = []
    for source in sources:
        current = saved.get(source.log_format)
        if current is None or source.format_spec is None:
            continue
        try:
            stored = spec_from_dict(source.format_spec)
        except FormatSpecError:
            continue
        if stored != current:
            drifts.append(
                FormatDrift(
                    file_id=source.file_id,
                    name=source.log_format,
                    stored=stored,
                    current=current,
                )
            )
    return drifts
