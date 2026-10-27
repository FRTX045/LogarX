"""The formats a user has saved, kept in a plain file they own.

This is the only piece of the format machinery the engine never reads. Ingest
resolves a format once and then carries the definition itself — into the
worker, and into the case — so this file exists purely to let the GUI and the
CLI *offer* a format that was written earlier. Losing it costs the user their
saved definitions and nothing else; every case stays readable.

That property is why the file can be plain, editable JSON in the user's config
directory rather than something guarded. It is also why a damaged file is
reported rather than replaced: starting from empty would silently discard saved
work at the moment the user most needs to hear about it.

Located by hand rather than through `platformdirs`. This is one function, the
project has six runtime dependencies and each of them earns its place — and the
`LOGARX_HOME` override the hand-rolled version needs anyway is the seam the
test suite uses to stay out of a real investigator's setup.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from logarx.parsers.spec import FormatSpecError, spec_from_dict, spec_to_dict

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarx.parsers.spec import FormatSpec

__all__ = [
    "LIBRARY_NAME",
    "LIBRARY_VERSION",
    "FormatLibraryError",
    "library_path",
    "load_library",
    "logarx_home",
    "move_old_home",
    "save_library",
]

LIBRARY_NAME: Final = "formats.json"

#: The shape of the file itself, which is not the shape of the definitions in
#: it — each of those carries its own version, so one new kind of format does
#: not oblige every reader to re-learn the envelope around it.
LIBRARY_VERSION: Final = 1


class FormatLibraryError(RuntimeError):
    """Raised when the saved-format file cannot be read or would be invalid."""


#: The folder's name before the tool was renamed, on 2026-10-28.
_OLD_HOME: Final = "logarc"


def _config_base() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


def logarx_home() -> Path:
    """Where LogarX keeps the things a user owns rather than a case does."""
    if override := os.environ.get("LOGARX_HOME"):
        return Path(override)
    return _config_base() / "LogarX"


def move_old_home(base: Path | None = None) -> bool:
    """Copy the folder the tool kept as logarc to LogarX's, once.

    Saved formats, rules and icons are the reader's own work, and a rename is
    no reason to lose them. Copied rather than moved, so the old folder stays
    as it was; through a staging folder, so a copy that fails part way leaves
    no half-filled new one to be taken for the real thing. Never over a new
    folder that exists, and never when `LOGARX_HOME` names one. Called once at
    start-up rather than from `logarx_home`, which a test suite calls freely.
    """
    if base is None:
        if os.environ.get("LOGARX_HOME"):
            return False
        base = _config_base()
    old, new = base / _OLD_HOME, base / "LogarX"
    if new.exists() or not old.is_dir():
        return False
    staging = base / "LogarX.moving"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        shutil.copytree(old, staging)
        staging.rename(new)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        return False
    return True


def library_path() -> Path:
    """The saved-format file. It need not exist; a first run has none."""
    return logarx_home() / LIBRARY_NAME


def load_library(path: Path | None = None) -> list[FormatSpec]:
    """Every saved format, in the order they were written.

    An absent file is not an error — that is a first run. A present file that
    cannot be understood is, and the message names the file so the user can go
    and look at it.
    """
    path = path or library_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise FormatLibraryError(f"{path} could not be read: {exc}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FormatLibraryError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise FormatLibraryError(f"{path} does not hold a saved-format library")

    version = payload.get("version")
    if not isinstance(version, int) or version > LIBRARY_VERSION:
        raise FormatLibraryError(
            f"{path} is library version {version}, and this LogarX reads up to "
            f"version {LIBRARY_VERSION}; it was written by a newer LogarX"
        )

    entries = payload.get("formats", [])
    if not isinstance(entries, list):
        raise FormatLibraryError(f"{path} has a 'formats' that is not a list")

    specs: list[FormatSpec] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise FormatLibraryError(f"{path} has an entry that is not a format definition")
        try:
            specs.append(spec_from_dict(entry))
        except FormatSpecError as exc:
            raise FormatLibraryError(f"{path}: {exc}") from exc
    return specs


def save_library(specs: Sequence[FormatSpec], path: Path | None = None) -> Path:
    """Replace the saved-format file with `specs`.

    Every entry is checked before anything is written, so a library that would
    not load back is never the thing on disk. Refusing here is the difference
    between a message now and a log that quarantines every one of its lines
    later — and unlike `load_library`, nothing forces a user to store a
    definition that will not compile, so nothing is lost by insisting.
    """
    path = path or library_path()
    _check(specs, path)

    payload: dict[str, Any] = {
        "version": LIBRARY_VERSION,
        "formats": [spec_to_dict(spec) for spec in specs],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    # Indented, because this file is meant to be openable in an editor: a user
    # who wants to copy a format to another machine should find something
    # readable when they get there.
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _check(specs: Sequence[FormatSpec], path: Path) -> None:
    seen: set[str] = set()
    for spec in specs:
        if not spec.name.strip():
            raise FormatLibraryError("a saved format needs a name")
        if spec.name in seen:
            # The name is how a case finds the library entry to compare itself
            # against; two entries sharing one would make that check ambiguous.
            raise FormatLibraryError(f"{path} would hold two formats named {spec.name!r}")
        seen.add(spec.name)
        try:
            # `check`, not `build`. A table format may not know its columns yet
            # — a W3C log declares them, so the definition is complete only
            # once a file is in hand, and the library has no file. Each kind
            # answers for as much of itself as can be judged from here.
            spec.check()
        except ValueError as exc:
            raise FormatLibraryError(f"format {spec.name!r} cannot be used: {exc}") from exc
