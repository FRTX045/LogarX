"""Writing a reconstruction out as a file, whoever asked for it.

The window and the command line each did this by hand, and had two copies of
the same two-branch decision along with two separate lists of which formats
exist. Two copies of a decision are two places for it to drift, and the drift
here has a shape worth naming: a dialog suggesting `graph.json` while the
writer puts HTML in it hands the reader a file that lies about itself, and
neither half would look wrong where it was written.

No Qt. Which formats exist and what each one produces are decisions, and a
decision should be checkable without starting a window - the same reason
`zodiarc.style` and `gui.prefs` have none.

PNG is not here. It is a picture of the canvas rather than a serialisation of
the reconstruction, so only something holding a canvas can produce it; the
window keeps that one.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from zodiarc.report.html import render_report

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from zodiarc.analysis import AnalysisResult
    from zodiarc.bookmarks import Shelf
    from zodiarc.core.evidence import EvidenceRef
    from zodiarc.evidence import EvidenceLine
    from zodiarc.storage.case import CaseManifest

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


def write_text(
    target: Path, text: str, *, encoding: str = "utf-8", newline: str | None = None
) -> None:
    """Write an exported document to `target`, whole or not at all.

    Every byte the log held that was not UTF-8 is written as that byte,
    spelled `\\xff` as Apache spells a byte it cannot print: a log line keeps
    such a byte as a lone surrogate, which no file can be encoded with.

    Written beside `target` first and moved over it once complete, so a write
    that fails leaves whatever file was there, and never an empty one.
    """
    shown = _bytes_spelled(text)
    partial = target.with_name(f".{target.name}.{os.getpid()}.part")
    try:
        with partial.open("w", encoding=encoding, newline=newline) as handle:
            handle.write(shown)
        partial.replace(target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def _bytes_spelled(text: str) -> str:
    """`text` with each byte kept as a surrogate spelled as the byte it was."""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        # A surrogate that is not a kept byte; spelled as its code point instead.
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


def write_reconstruction(
    result: AnalysisResult,
    manifest: CaseManifest,
    *,
    kind: str,
    target: Path,
    shelf: Shelf | None = None,
    lines: Mapping[EvidenceRef, EvidenceLine] | None = None,
    client_name: str | None = None,
) -> Path:
    """Write `result` to `target` in the format `kind` names, and say where.

    Hands the path back rather than leaving each caller to work out again what
    it passed in: both of them report where the file went, and one of them does
    it from a worker thread. `shelf` and `lines` are the case's bookmarks and
    the log lines behind them, for the report's Bookmarks section. `client_name`
    is the name a reader gave the client: the report shows it beside the
    address, and the JSON gains a `client_name` field beside `client_ip`, only
    when there is one, so a reader of the JSON as it was sees nothing change.
    """
    fmt = named(kind)
    if fmt.kind == "json":
        data = result.to_dict()
        if client_name:
            data = {**data, "client_name": client_name}
        write_text(target, json.dumps(data, indent=2))
    else:
        write_text(
            target,
            render_report(result, manifest, shelf=shelf, lines=lines, client_name=client_name),
        )
    return target
