"""The window speaks one vocabulary.

Renamed on 2026-10-21: the first tab is Triage, the graph tab is Activity, a
row in the list is a client, where activities sit is a layout, and a case made
from log files is "new from logs". A phrase from before that, left in one
message, makes the window sound like two programs. This reads every string the
interface code can show — string literals outside docstrings — and fails on
any retired phrase, naming the file and line.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "src" / "logarx"
SHOWN = [*sorted((SOURCE / "gui").glob("*.py")), SOURCE / "search.py"]

RETIRED = (
    "Where to start",
    "Reconstruction",
    "Inspect IP",
    "Graph key",
    "Whole case",
    "range is now the whole case",
    "Forget these",
    "Ingest logs",
    "Ingesting",
    "Ingest cancelled",
    "Original log line",
    "Recently opened",
    "on this case",
    "this arrangement",
    "This arrangement",
    "Arrangement saved",
    "Unsaved arrangement",
    "you have arranged",
    "Save arrangement",
    "saved arrangement",
    "unsaved arrangement",
    "IP address",
    "IPs",
    "quarantined lines",
    "Re-ingest",
    "Select an IP",
    "Reconstructing",
    "reconstructed activity",
    "reconstruction reports",
    "ingested",
    "re-ingesting",
    "ingesting the same",
    "IP may represent",
    "Searching the whole case",
    "search the whole case",
)


def _docstrings(tree: ast.AST) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            found.add(id(node.value))
    return found


def _shown_strings(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstrings(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append((node.lineno, node.value))
    return found


@pytest.mark.parametrize("path", SHOWN, ids=lambda p: p.name)
def test_no_retired_phrase_reaches_the_screen(path: Path) -> None:
    offenders = [
        f"{path.name}:{line}: {phrase!r} in {text!r}"
        for line, text in _shown_strings(path)
        for phrase in RETIRED
        if phrase in text
    ]

    assert not offenders, "\n".join(offenders)
