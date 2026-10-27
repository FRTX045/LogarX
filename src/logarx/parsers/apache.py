"""Apache's named log formats.

These are the directive strings Apache ships as `common`, `combined` and
`vhost_combined`. They are ordinary input to `LogFormatParser` — there is no
special-case code path for them, which is the point: a site using a custom
`LogFormat` is supported by writing its directive string down instead.

They live here rather than in `parsers.builtins` because several of the
built-ins are built *from* them: `apache-combined-io` is combined plus two
counts, and `nginx-combined-forwarded` is combined plus two more fields. Spelled
out separately those three would drift.
"""

from __future__ import annotations

from typing import Final

COMMON: Final = '%h %l %u %t "%r" %>s %b'
COMBINED: Final = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
VHOST_COMBINED: Final = '%v:%p %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

__all__ = ["COMBINED", "COMMON", "VHOST_COMBINED"]
