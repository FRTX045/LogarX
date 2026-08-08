"""Parser lookup and log format auto-detection.

Detection scores each known format by the fraction of a sample it can parse.
This works because the Apache presets are mutually exclusive in practice: a
combined line carries two quoted fields that `common` has no place for, and a
vhost line begins with a `host:port` token that `combined` cannot match.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.core.evidence import EvidenceRef
from logarc.parsers.apache import PRESETS
from logarc.parsers.logformat import LogFormatParser

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from logarc.parsers.base import LogParser

__all__ = [
    "FormatDetection",
    "UnknownFormatError",
    "available_formats",
    "detect_format",
    "get_parser",
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


def available_formats() -> list[str]:
    """Registered format names, most specific first."""
    return list(PRESETS)


def get_parser(name: str) -> LogFormatParser:
    """Build the parser registered under `name`."""
    try:
        log_format = PRESETS[name]
    except KeyError:
        known = ", ".join(PRESETS)
        raise UnknownFormatError(f"unknown log format {name!r}; available: {known}") from None
    return LogFormatParser(log_format, name=name)


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
    for name in PRESETS:
        parser = get_parser(name)
        confidence = score_parser(parser, lines)
        if confidence >= min_confidence and (best is None or confidence > best.confidence):
            best = FormatDetection(name=name, parser=parser, confidence=confidence)
    return best
