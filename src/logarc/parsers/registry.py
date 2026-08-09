"""Parser lookup, registration and log format auto-detection.

Detection scores each known format by the fraction of a sample it can parse.
This works because the Apache presets are mutually exclusive in practice: a
combined line carries two quoted fields that `common` has no place for, and a
vhost line begins with a `host:port` token that `combined` cannot match.

The registry is open. `LogParser` being a Protocol only makes a new format
*expressible*; it takes a way to register one to make it reachable, otherwise
the extension point is a preset list with extra steps. Anything satisfying the
protocol can be added here and is then available to `logarc ingest --format`,
to auto-detection, and to the window's format dropdown, without a change
anywhere else. See docs/adding-a-parser.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.core.evidence import EvidenceRef
from logarc.parsers.apache import PRESETS
from logarc.parsers.logformat import LogFormatParser

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from logarc.parsers.base import LogParser

__all__ = [
    "FormatDetection",
    "FormatEntry",
    "UnknownFormatError",
    "available_formats",
    "detect_format",
    "get_parser",
    "register_format",
    "register_logformat",
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


@dataclass(frozen=True, slots=True)
class FormatEntry:
    """One registered format: how to build it, and how to describe it."""

    name: str
    factory: Callable[[], LogParser]
    description: str = ""
    """Shown by `logarc formats`. The LogFormat directive, where there is one."""


def _apache_entry(name: str, directive: str) -> FormatEntry:
    # Built in a function rather than inline in the comprehension below: the
    # lambda closes over these parameters, which are bound once per call, where
    # closing over a comprehension's loop variable would leave every preset
    # building the last directive in the dict.
    return FormatEntry(
        name=name,
        factory=lambda: LogFormatParser(directive, name=name),
        description=directive,
    )


#: Registration order is preference order. Detection compares confidence first
#: and only falls back to this on a tie, so the built-ins stay ahead of anything
#: added later — a new format cannot quietly take over logs that already parse.
_REGISTRY: Final[dict[str, FormatEntry]] = {
    name: _apache_entry(name, directive) for name, directive in PRESETS.items()
}


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


def register_logformat(name: str, directive: str) -> None:
    """Register an Apache- or nginx-style format from its directive string."""
    register_format(
        name,
        lambda: LogFormatParser(directive, name=name),
        description=directive,
    )


def unregister_format(name: str) -> None:
    """Remove a registered format. Unknown names are ignored."""
    _REGISTRY.pop(name, None)


def registered_formats() -> list[FormatEntry]:
    """Every registered format, in preference order."""
    return list(_REGISTRY.values())


def available_formats() -> list[str]:
    """Registered format names, most specific first."""
    return list(_REGISTRY)


def get_parser(name: str) -> LogParser:
    """Build the parser registered under `name`."""
    try:
        entry = _REGISTRY[name]
    except KeyError:
        known = ", ".join(_REGISTRY)
        raise UnknownFormatError(f"unknown log format {name!r}; available: {known}") from None
    return entry.factory()


def score_parser(parser: LogParser, lines: Sequence[str]) -> float:
    """Fraction of non-blank `lines` that `parser` accepts."""
    considered = 0
    accepted = 0
    for line in lines:
        if not line.strip():
            continue
        considered += 1
        if parser.parse_line(line, _DETECTION_REF) is not None:
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
    lines = [line for line in sample][:sample_size]  # noqa: C416 - accepts any iterable
    if not any(line.strip() for line in lines):
        return None

    best: FormatDetection | None = None
    for name in _REGISTRY:
        parser = get_parser(name)
        confidence = score_parser(parser, lines)
        if confidence >= min_confidence and (best is None or confidence > best.confidence):
            best = FormatDetection(name=name, parser=parser, confidence=confidence)
    return best
