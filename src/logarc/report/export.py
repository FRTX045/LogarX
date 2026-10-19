"""Writing a reconstruction out as a file, whoever asked for it.

The window and the command line each did this by hand, and had two copies of
the same two-branch decision along with two separate lists of which formats
exist. Two copies of a decision are two places for it to drift, and the drift
here has a shape worth naming: a dialog suggesting `graph.json` while the
writer puts HTML in it hands the reader a file that lies about itself, and
neither half would look wrong where it was written.

No Qt. Which formats exist and what each one produces are decisions, and a
decision should be checkable without starting a window - the same reason
`logarc.style` and `gui.prefs` have none.

PNG is not here. It is a picture of the canvas rather than a serialisation of
the reconstruction, so only something holding a canvas can produce it; the
window keeps that one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.report.html import render_report

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from logarc.analysis import AnalysisResult
    from logarc.bookmarks import Shelf
    from logarc.core.evidence import EvidenceRef
    from logarc.storage.case import CaseManifest

__all__ = ["FORMATS", "Format", "named", "write_reconstruction"]


@dataclass(frozen=True, slots=True)
class Format:
    """One way of writing a reconstruction out."""

    kind: str
    """What a caller asks for, and what `--format` takes."""

    label: str
    """What to call it to a reader. The window titles its dialog with this."""

    suffix: str
    """The extension, including the dot.

    Here rather than in the caller because it is the half that can disagree
    with what gets written, and the two can only be held together by being in
    one place.
    """

    @property
    def suggested(self) -> str:
        """A filename to open the save dialog on."""
        return f"{'report' if self.kind == 'html' else 'graph'}{self.suffix}"

    @property
    def mask(self) -> str:
        """The filter string a file dialog wants."""
        return f"{self.label.split()[0]} (*{self.suffix})"


#: In the order they are offered. A dialog is read top to bottom and remembered
#: by position, so this is not an arbitrary tuple.
FORMATS: Final = (
    Format(kind="html", label="HTML report", suffix=".html"),
    Format(kind="json", label="JSON graph", suffix=".json"),
)


def named(kind: str) -> Format:
    """The format `kind` asks for.

    Refuses by name, and says what was on offer: "unknown format" alone leaves
    the reader guessing, and the guess they make is usually the extension
    rather than the name.
    """
    for fmt in FORMATS:
        if fmt.kind == kind:
            return fmt
    choices = " or ".join(fmt.kind for fmt in FORMATS)
    raise ValueError(f"unknown format {kind!r}; choose {choices}")


def write_reconstruction(
    result: AnalysisResult,
    manifest: CaseManifest,
    *,
    kind: str,
    target: Path,
    shelf: Shelf | None = None,
    lines: Mapping[EvidenceRef, str] | None = None,
) -> Path:
    """Write `result` to `target` in the format `kind` names, and say where.

    Hands the path back rather than leaving each caller to work out again what
    it passed in: both of them report where the file went, and one of them does
    it from a worker thread. `shelf` and `lines` are the case's bookmarks and
    the log lines behind them, for the report's Bookmarks section.
    """
    fmt = named(kind)
    if fmt.kind == "json":
        target.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    else:
        target.write_text(
            render_report(result, manifest, shelf=shelf, lines=lines), encoding="utf-8"
        )
    return target
