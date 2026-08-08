"""Reduce a request's text to a canonical form before matching rules on it.

Signatures match text, and attackers know it. `%2553ELECT`, `UNI/**/ON`,
fullwidth `ＳＥＬＥＣＴ` and `SeLeCt` are all the same request to the server and
four different strings to a naive rule. Undoing those transformations is what
makes a small ruleset hold up; without it, every rule needs a variant per
evasion and still misses the next one.

The decode depth is kept rather than discarded: ordinary traffic is encoded once,
so anything beyond that is a deliberate act and is itself worth reporting.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote, unquote_plus

__all__ = ["DEFAULT_MAX_DEPTH", "NormalizedText", "normalize"]

#: How many times to re-apply percent-decoding before giving up. Three covers
#: every layering seen in practice while bounding the work a crafted input can
#: cause.
DEFAULT_MAX_DEPTH: Final = 3

_SQL_BLOCK_COMMENT: Final = re.compile(r"/\*.*?\*/", re.DOTALL)
_WHITESPACE_RUN: Final = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class NormalizedText:
    """The canonical form of one piece of request text, plus what it took."""

    text: str
    decode_depth: int
    """Rounds of percent-decoding applied before the text stopped changing."""
    truncated_decoding: bool
    """True when the depth limit was reached and more encoding remained."""

    @property
    def multiply_encoded(self) -> bool:
        """Whether the text was encoded more than once.

        Legitimate clients encode once. Repeated encoding is a deliberate
        attempt to look like something else, and is a signal on its own
        regardless of what the decoded payload turns out to be.
        """
        return self.decode_depth > 1


def normalize(
    text: str | None,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    plus_is_space: bool = False,
) -> NormalizedText:
    """Canonicalise `text` for rule matching.

    Applied in order: recursive percent-decoding, Unicode compatibility folding,
    case folding, SQL comment removal, whitespace collapsing.

    `plus_is_space` is for text that is form-encoded — a query string, or a
    body folded into one. There a `+` means a space, which is how every HTML
    form and most attack tools write one, and reading it literally leaves
    `1'+or+'1'='1` with no whitespace for a rule to match on. It is off by
    default because a path, a Referer and a User-Agent are not form data, and a
    `+` in those is a `+`.

    Invalid escapes such as `%zz` are left as-is rather than guessed at — they
    are evidence, and rewriting them would misrepresent what was sent.
    """
    if not text:
        return NormalizedText(text="", decode_depth=0, truncated_decoding=False)

    decoded, depth, truncated = _percent_decode(text, max_depth, plus_is_space=plus_is_space)

    # Compatibility folding turns lookalikes (fullwidth, ligatures) into the
    # ASCII a rule is written against.
    folded = unicodedata.normalize("NFKC", decoded).casefold()

    without_comments = _SQL_BLOCK_COMMENT.sub("", folded)
    collapsed = _WHITESPACE_RUN.sub(" ", without_comments).strip()

    return NormalizedText(text=collapsed, decode_depth=depth, truncated_decoding=truncated)


def _percent_decode(text: str, max_depth: int, *, plus_is_space: bool) -> tuple[str, int, bool]:
    """Percent-decode until the text stops changing or the limit is hit."""
    decode = unquote_plus if plus_is_space else unquote
    current = text
    depth = 0
    for _ in range(max_depth):
        # `errors="strict"` would raise on malformed UTF-8 sequences, which are
        # exactly what hostile input contains; surrogate escapes keep the bytes.
        candidate = decode(current, errors="surrogateescape")
        if candidate == current:
            return current, depth, False
        current = candidate
        depth += 1

    still_encoded = decode(current, errors="surrogateescape") != current
    return current, depth, still_encoded
