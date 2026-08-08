"""Apache's named log formats.

These are the directive strings Apache ships as `common`, `combined` and
`vhost_combined`. They are ordinary input to `LogFormatParser` — there is no
special-case code path for them, which is the point: a site using a custom
`LogFormat` is supported by passing its directive string instead.
"""

from __future__ import annotations

from typing import Final

COMMON: Final = '%h %l %u %t "%r" %>s %b'
COMBINED: Final = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
VHOST_COMBINED: Final = '%v:%p %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

#: Named presets, ordered most specific first so that auto-detection prefers the
#: format carrying the most information when several would match.
PRESETS: Final[dict[str, str]] = {
    "apache-vhost-combined": VHOST_COMBINED,
    "apache-combined": COMBINED,
    "apache-common": COMMON,
}

__all__ = ["COMBINED", "COMMON", "PRESETS", "VHOST_COMBINED"]
