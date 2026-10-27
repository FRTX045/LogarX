"""Parser lookup, registration and log format auto-detection.

Detection scores each known format by the fraction of a sample it can parse.
This works because the Apache presets are mutually exclusive in practice: a
combined line carries two quoted fields that `common` has no place for, and a
vhost line begins with a `host:port` token that `combined` cannot match.

The registry is open. `LogParser` being a Protocol only makes a new format
*expressible*; it takes a way to register one to make it reachable, otherwise
the extension point is a preset list with extra steps. Anything satisfying the
protocol can be added here and is then available to the window and `logarc-dev ingest --format`,
to auto-detection, and to the window's format chooser, without a change
anywhere else. See docs/adding-a-parser.md.

Two ways in, and the difference between them matters. `register_spec` takes a
definition — data, which can be pickled to a worker and written into a case.
`register_format` takes a factory — code, which can do neither. Both are
reachable by name in this process; only the first survives leaving it. The
registry says which it holds, through `get_spec` returning `None`, so a caller
can fall back rather than silently carry nothing.

Nothing here reads the user's saved-format library. `register_saved_formats`
does, and the CLI and the GUI call it — never the engine, which must work from
what it was handed. See `logarc.parsers.library`.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
from typing import TYPE_CHECKING, Final

from logarc.core.evidence import EvidenceRef
from logarc.parsers.base import skips
from logarc.parsers.builtins import BUILT_INS
from logarc.parsers.library import load_library
from logarc.parsers.spec import LogFormatSpec

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from logarc.parsers.base import LogParser
    from logarc.parsers.spec import FormatSpec

__all__ = [
    "FormatDetection",
    "FormatEntry",
    "UnknownFormatError",
    "available_formats",
    "detect_format",
    "get_parser",
    "get_spec",
    "is_built_in",
    "register_format",
    "register_logformat",
    "register_saved_formats",
    "register_spec",
    "registered_formats",
    "unregister_format",
]

#: Below this share of parseable lines, a format is not considered a match.
DEFAULT_MIN_CONFIDENCE: Final = 0.6

#: Detection never needs the whole file; this many lines settles it.
DEFAULT_SAMPLE_SIZE: Final = 200

_DETECTION_REF: Final = EvidenceRef(source_file_id="<detect>", line_no=0)


class UnknownFormatError(LookupError):
    """Raised when a format name is not registered."""


@dataclass(frozen=True, slots=True)
class FormatDetection:
    """The best-matching format for a sample, and how well it matched."""

    name: str
    parser: LogParser
    confidence: float
    """Share of non-blank sample lines the parser accepted, 0.0 to 1.0."""

    spec: FormatSpec | None = None
    """The definition behind the name, when there is one to carry.

    `None` for a format registered by handing over a factory. Ingest reads this
    to decide whether it can send the format itself to a worker and record it in
    the case, or has to fall back to the name."""


@dataclass(frozen=True, slots=True)
class FormatEntry:
    """One registered format: how to build it, and how to describe it."""

    name: str
    factory: Callable[[], LogParser]
    description: str = ""
    """Shown in the format editor. The LogFormat directive, where there is one."""

    spec: FormatSpec | None = None
    """The definition, for a format registered from one. See `get_spec`."""


def _entry_for(spec: FormatSpec) -> FormatEntry:
    # `spec.build` rather than a lambda closing over the spec: the closure used
    # to be the subtle part here, because one bound per comprehension iteration
    # left every preset building the last directive in the dict. A bound method
    # cannot have that fault.
    return FormatEntry(
        name=spec.name,
        factory=spec.build,
        description=spec.summary,
        spec=spec,
    )


#: Registration order is preference order. Detection compares confidence first
#: and only falls back to this on a tie, so the built-ins stay ahead of anything
#: added later — a new format cannot quietly take over logs that already parse.
_REGISTRY: Final[dict[str, FormatEntry]] = {spec.name: _entry_for(spec) for spec in BUILT_INS}


def register_format(name: str, factory: Callable[[], LogParser], *, description: str = "") -> None:
    """Make a log format available everywhere a built-in one is.

    `factory` is called per use rather than being handed a parser instance,
    because auto-detection builds one parser per candidate format and ingest
    shares a parser across workers; a factory keeps both honest without the
    registry having to know which is happening.
    """
    if name in _REGISTRY:
        raise ValueError(
            f"log format {name!r} is already registered; "
            "pick another name or unregister the existing one first"
        )
    _REGISTRY[name] = FormatEntry(name=name, factory=factory, description=description)


def register_spec(spec: FormatSpec) -> None:
    """Make a log format available from its definition rather than its code.

    Preferred over `register_format` wherever there is a definition to hand
    over: only this form can reach an ingest worker or be recorded in a case.
    """
    if spec.name in _REGISTRY:
        raise ValueError(
            f"log format {spec.name!r} is already registered; "
            "pick another name or unregister the existing one first"
        )
    _REGISTRY[spec.name] = _entry_for(spec)


def register_logformat(name: str, directive: str) -> None:
    """Register an Apache-style format from its directive string."""
    register_spec(LogFormatSpec(name=name, directive=directive))


#: Names this process installed from the saved-format library, so a later call
#: can take them out again. Without it the registry only ever grows: a GUI that
#: refreshes after the user deletes a format would keep offering the deleted
#: one, and a second call would leave a stale definition behind a live name.
_FROM_LIBRARY: Final[set[str]] = set()


def register_saved_formats() -> list[FormatSpec]:
    """Install the user's saved formats, and report which ones were installed.

    Also a refresh: whatever a previous call installed is removed first, so
    calling this after the library changes leaves the registry agreeing with
    the file rather than with the union of every version of it.

    Called by the CLI and the GUI at startup, never by the engine: a worker
    parses with the definition it was handed and a case is read from the copy it
    stored, so neither needs — or should depend on — a file in a home directory.

    A saved format whose name is already taken is skipped rather than allowed to
    displace what is there. Registration order is preference order, so letting
    one shadow `apache-combined` would change what an existing case means.
    Skipping shows as an absence from the returned list.

    Calling it twice is not an error; the second call installs nothing.
    """
    for name in _FROM_LIBRARY:
        _REGISTRY.pop(name, None)
    _FROM_LIBRARY.clear()

    installed: list[FormatSpec] = []
    for spec in load_library():
        if spec.name in _REGISTRY:
            continue
        _REGISTRY[spec.name] = _entry_for(spec)
        _FROM_LIBRARY.add(spec.name)
        installed.append(spec)
    return installed


def unregister_format(name: str) -> None:
    """Remove a registered format. Unknown names are ignored."""
    _REGISTRY.pop(name, None)


def registered_formats() -> list[FormatEntry]:
    """Every registered format, in preference order."""
    return list(_REGISTRY.values())


def available_formats() -> list[str]:
    """Registered format names, most specific first."""
    return list(_REGISTRY)


def _entry(name: str) -> FormatEntry:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(_REGISTRY)
        raise UnknownFormatError(f"unknown log format {name!r}; available: {known}") from None


def get_parser(name: str) -> LogParser:
    """Build the parser registered under `name`."""
    return _entry(name).factory()


def is_built_in(name: str) -> bool:
    """Whether `name` is a format this logarc ships, rather than a saved one.

    Asked here rather than worked out by the caller from `available_formats()`
    minus the library file. Those two are the same only while the registry and
    the file agree, and reconciling them is this module's job — a caller doing
    the subtraction itself gets the wrong answer whenever the file has changed
    since the last `register_saved_formats`, and calls a user's own format a
    built-in.
    """
    return name in _REGISTRY and name not in _FROM_LIBRARY


def get_spec(name: str) -> FormatSpec | None:
    """The definition behind `name`, or `None` if it has none to give.

    `None` is not a failure. It means the format was registered by handing over
    a factory, which is code, and code cannot be written into a case or sent to
    a worker. An unknown name *is* a failure, and raises.
    """
    return _entry(name).spec


def score_parser(parser: LogParser, lines: Sequence[str]) -> float:
    """Fraction of `lines` that `parser` accepts, ignoring what it calls its own.

    A W3C log opens with four directives and a CSV with a header row. Counted
    as lines the parser failed to read, a short sample of such a log scores far
    below the threshold and the format written for it is passed over — which is
    how `iis-w3c` failed to be detected on an IIS log.

    A parser that raises on a line has not accepted it. Detection tries every
    registered format, so one format's bug used to end detection for all of
    them, and the ingest with it.
    """
    considered = 0
    accepted = 0
    for line in lines:
        if not line.strip() or skips(parser, line):
            continue
        considered += 1
        try:
            event = parser.parse_line(line, _DETECTION_REF)
        except MemoryError:
            raise
        except Exception:
            continue
        if event is not None:
            accepted += 1
    return accepted / considered if considered else 0.0


def detect_format(
    sample: Iterable[str],
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> FormatDetection | None:
    """Identify which registered format a sample of log lines is written in.

    Returns `None` when nothing matches well enough, which the caller should
    surface as "tell me the format" rather than guessing — silently picking a
    wrong parser would quarantine an entire log and look like an empty result.
    """
    lines = list(islice(sample, sample_size))
    if not any(line.strip() for line in lines):
        return None

    best: FormatDetection | None = None
    for name in _REGISTRY:
        # Resolved against the sample before it is scored. A table format's
        # columns may be declared in the file rather than in the definition,
        # and unresolved it cannot read a line — it would score zero and be
        # passed over for the very logs it was written for.
        spec = _REGISTRY[name].spec
        try:
            resolved = spec.resolved(lines) if spec is not None else None
            parser = resolved.build() if resolved is not None else get_parser(name)
        except ValueError:
            # A definition that cannot be built against this file is simply not
            # the format of this file. Detection says so by moving on.
            continue
        confidence = score_parser(parser, lines)
        if confidence >= min_confidence and (best is None or confidence > best.confidence):
            best = FormatDetection(name=name, parser=parser, confidence=confidence, spec=resolved)
    return best
