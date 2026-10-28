"""Reading a timestamp out of a log field, in the shapes logs actually use.

Shared by every format kind that is not an Apache directive. The directive
compiler keeps its own hand-sliced CLF path, which is about ten times quicker
than `strptime` and runs on every line of the commonest log there is; these are
for the kinds where the shape is not known in advance.

One rule holds across all of them: **a stamp carrying no offset is read as
UTC.** Reading it in the machine's own zone would make one log parse to
different instants on two machines, and a case may not do that.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Final

__all__ = ["TimeFormatError", "check_time_format", "read_time"]


class TimeFormatError(ValueError):
    """Raised when a time format could not date an event even if it matched."""


#: The strftime directives that carry a year. A pattern with none of them is
#: refused: `strptime` supplies 1900 for the missing year, so every event of
#: such a log lands there together — and in a report that reads "the attack
#: occurred on 1 May 1900". The ordering inside the file survives; the date
#: does not, and a date is what evidence is pinned to.
_YEAR_DIRECTIVES: Final[tuple[str, ...]] = ("%Y", "%y", "%G", "%c", "%x", "%s")


def check_time_format(time_format: str) -> None:
    """Refuse a time format that could not date an event even if it matched.

    Asked when a format is written rather than once per line, so the reader
    hears it while they can still do something about it. An empty format is
    fine: nothing was promised, and `read_time` then reads ISO or epoch, both
    of which carry a year.
    """
    if not time_format:
        return
    if not any(directive in time_format for directive in _YEAR_DIRECTIVES):
        raise TimeFormatError(
            f"the time format {time_format!r} says nothing about the year, so every "
            "event would be dated 1900. Add %Y — or if the log truly does not record "
            "a year, it cannot be used to date evidence"
        )


#: Tried in turn when no format was given. `fromisoformat` covers most of
#: ISO 8601 on the versions this project supports; these are the spellings it
#: does not, and they are common enough to be worth the extra attempts.
_FALLBACKS: Final[tuple[str, ...]] = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y %H:%M:%S",
)

#: Above this, a number is milliseconds rather than seconds. 1e11 seconds is
#: the year 5138 and 1e11 milliseconds is 1973, so nothing real is ambiguous —
#: and read as seconds a millisecond stamp lands in the year 56,000 and sorts
#: last for ever without anything downstream questioning it.
_MILLIS_ABOVE: Final = 1e11
_MICROS_ABOVE: Final = 1e14
#: Cloudflare Logpush's default, `unixnano`. 1e17 nanoseconds is 1973 again,
#: and 1e17 microseconds is the year 5138.
_NANOS_ABOVE: Final = 1e17

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

#: Below this, a number is not a timestamp at all. 1e8 seconds is March 1973,
#: before any web server existed, so nothing real is lost — and what is caught
#: is a field misidentified as the time: a regex group or a column that holds a
#: small number reads as an instant in 1970, and every event a log produced
#: lands there together, sorted and plotted and believed.
_EPOCH_FLOOR: Final = 1e8


def _in_utc(parsed: datetime) -> datetime:
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)


def _from_epoch(number: float) -> datetime | None:
    if abs(number) < _EPOCH_FLOOR:
        return None
    # Added to the epoch rather than handed to `fromtimestamp`, which raises
    # past the year 3000 on Windows and not on Linux. A number past what
    # `datetime` can hold, or not a number at all, is not a time: one such line
    # raising here used to end the ingest of the whole log. The division is
    # inside too, because an integer too large for a float raises there first.
    try:
        if abs(number) > _NANOS_ABOVE:
            number /= 1_000_000_000
        elif abs(number) > _MICROS_ABOVE:
            number /= 1_000_000
        elif abs(number) > _MILLIS_ABOVE:
            number /= 1000
        return _EPOCH + timedelta(seconds=number)
    except (OverflowError, ValueError):
        return None


def _as_number(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _told(text: str, time_format: str) -> datetime | None:
    """Read with the pattern the format was given, and no second guesses.

    The reader said what this field is. Quietly reading it some other way would
    make a pattern that does not work look as though it does.
    """
    try:
        return _in_utc(datetime.strptime(text, time_format))
    except ValueError:
        return None


def _guessed(text: str) -> datetime | None:
    """Read a stamp the format did not describe: ISO first, then epoch."""
    # `Z` spelled out, because `fromisoformat` did not accept it before 3.12
    # and this project supports 3.11.
    candidate = f"{text[:-1]}+00:00" if text.endswith(("Z", "z")) else text
    try:
        return _in_utc(datetime.fromisoformat(candidate))
    except ValueError:
        pass
    for fmt in _FALLBACKS:
        try:
            return _in_utc(datetime.strptime(candidate, fmt))
        except ValueError:
            continue
    number = _as_number(text)
    return _from_epoch(number) if number is not None else None


def read_time(value: Any, time_format: str = "") -> datetime | None:
    """The timestamp `value` holds, or `None` if it does not hold one.

    A number is epoch, in whichever of seconds, milliseconds or microseconds
    its magnitude says. Text is ISO unless `time_format` says otherwise.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(value)

    text = str(value).strip()
    if not text:
        return None
    return _told(text, time_format) if time_format else _guessed(text)
