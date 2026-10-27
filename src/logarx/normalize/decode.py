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
from functools import lru_cache
from typing import Final
from urllib.parse import unquote, unquote_plus

__all__ = ["DEFAULT_MAX_DEPTH", "NormalizedText", "canonical_path", "normalize"]

#: How many times to re-apply percent-decoding before giving up. Three covers
#: every layering seen in practice while bounding the work a crafted input can
#: cause.
DEFAULT_MAX_DEPTH: Final = 3

_SQL_BLOCK_COMMENT: Final = re.compile(r"/\*.*?\*/", re.DOTALL)
_WHITESPACE_RUN: Final = re.compile(r"\s+")

#: Numeric character references and the handful of named ones that carry a
#: payload. Deliberately not `html.unescape`, which is permissive by design: it
#: decodes named entities with no trailing semicolon, so `&notit;` becomes
#: `¬it;` and an ordinary query string starts matching rules it should not.
#: Everything here requires the semicolon.
#: The digit bound is generous rather than tight because padding a codepoint
#: with leading zeros is itself an evasion — the CRS corpus writes `&#` followed
#: by 47 zeros and then `123`. Bounded all the same, so a crafted input cannot
#: hand `int()` a megabyte of digits.
_HTML_ENTITY: Final = re.compile(
    r"&(?:#(\d{1,64})|#x([0-9a-fA-F]{1,64})|(lt|gt|amp|quot|apos|nbsp));"
)

_NAMED_ENTITIES: Final[dict[str, str]] = {
    "lt": "<",
    "gt": ">",
    "amp": "&",
    "quot": '"',
    "apos": "'",
    "nbsp": " ",
}

#: JavaScript hex and unicode escapes. Octal (`\123`) is deliberately absent:
#: it would rewrite `C:\Windows\123` into `C:\WindowsS`, and a Windows path is
#: exactly what the traversal payloads in a request line look like. No measured
#: payload needs it. The single-character escapes (`\\`, `\"`, `\n`) are absent
#: for the same reason and the same lack of benefit.
_JS_ESCAPE: Final = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))")


@dataclass(frozen=True, slots=True)
class NormalizedText:
    """The canonical form of one piece of request text, plus what it took."""

    text: str
    decode_depth: int
    """Rounds of percent-decoding applied before the text stopped changing.

    Percent-decoding only. Entity and JavaScript escapes are undone in the same
    loop but do not count here, because this number answers "how many layers of
    URL encoding" — the question `multiply_encoded_request` is asking — and
    folding a second encoding scheme into it would quietly change what that
    rule fires on."""
    truncated_decoding: bool
    """True when the depth limit was reached and more encoding remained."""
    had_null: bool = False
    """True when a null byte was present before it was stripped.

    The null is removed from `text` so that `/etc/passwd%00.jpg` reaches the
    rules as the path it actually opens. Removing it silently would discard a
    signal — no legitimate client sends one — so the fact is kept here, the
    same way `decode_depth` keeps the fact of multiple encoding after the
    encoding itself has been undone."""

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

    Applied in order: recursive decoding (percent, HTML entity and JavaScript
    escapes, to a fixed point), null removal, Unicode compatibility folding,
    case folding, SQL comment removal, whitespace collapsing.

    The three decoders run in one loop rather than in sequence because they
    nest: `%26lt%3B` is percent-then-entity, and `&#x25;3C` is entity-then-
    percent. Running each once, in whatever order, leaves half of those still
    encoded.

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
        return NormalizedText(text="", decode_depth=0, truncated_decoding=False, had_null=False)

    decoded, depth, truncated = _decode(text, max_depth, plus_is_space=plus_is_space)

    # A null truncates the filename for the code that opens it while leaving the
    # extension visible to whatever checked it. Stripped so a rule sees the path
    # that is actually reached; recorded because sending one is never accidental.
    had_null = "\x00" in decoded
    without_nulls = decoded.replace("\x00", "") if had_null else decoded

    # Compatibility folding turns lookalikes (fullwidth, ligatures) into the
    # ASCII a rule is written against.
    folded = unicodedata.normalize("NFKC", without_nulls).casefold()

    without_comments = _SQL_BLOCK_COMMENT.sub("", folded)
    collapsed = _WHITESPACE_RUN.sub(" ", without_comments).strip()

    return NormalizedText(
        text=collapsed,
        decode_depth=depth,
        truncated_decoding=truncated,
        had_null=had_null,
    )


def _decode(text: str, max_depth: int, *, plus_is_space: bool) -> tuple[str, int, bool]:
    """Undo the encodings until the text stops changing or the limit is hit.

    `depth` counts only the rounds in which percent-decoding did something, so
    text carrying no percent-encoding is reported at the depth it has always
    been reported at.
    """
    percent = unquote_plus if plus_is_space else unquote
    current = text
    depth = 0

    for _ in range(max_depth):
        # `errors="strict"` would raise on malformed UTF-8 sequences, which are
        # exactly what hostile input contains; surrogate escapes keep the bytes.
        unquoted = percent(current, errors="surrogateescape")
        if unquoted != current:
            depth += 1

        candidate = _js_decode(_entity_decode(unquoted))
        if candidate == current:
            return current, depth, False
        current = candidate

    still_encoded = (
        _js_decode(_entity_decode(percent(current, errors="surrogateescape"))) != current
    )
    return current, depth, still_encoded


def _entity_decode(text: str) -> str:
    """Resolve numeric and common named HTML entities."""
    if "&" not in text:
        return text
    return _HTML_ENTITY.sub(_entity_replacement, text)


def _entity_replacement(match: re.Match[str]) -> str:
    decimal, hexadecimal, name = match.groups()
    if name is not None:
        return _NAMED_ENTITIES[name]
    try:
        # Leading zeros are legal and are themselves an evasion: the corpus
        # writes `&#00000000000000000000000000000000000000000000000123;`.
        return chr(int(decimal) if decimal is not None else int(hexadecimal, 16))
    except (ValueError, OverflowError):
        # Not a codepoint. Left as written rather than guessed at, for the same
        # reason `%zz` is: it is evidence.
        return match.group(0)


def _js_decode(text: str) -> str:
    """Resolve `\\xHH` and `\\uHHHH` escapes."""
    if "\\" not in text:
        return text
    return _JS_ESCAPE.sub(lambda match: chr(int(match.group(1) or match.group(2), 16)), text)


@lru_cache(maxsize=8192)
def canonical_path(path: str | None) -> str:
    """Reduce a path to the resource it names, for *counting* distinct paths.

    `/a/b`, `/a//b` and `/a/./b` are one resource written three ways. Counted
    literally they are three, which matters because `distinct_paths` is a
    threshold in three of the bundled window rules: the inflation pushes
    `directory_enumeration` over its `>= 15` and can push `credential_attack`
    over its `<= 3`, so a request path written unusually changes whether a
    behaviour is detected at all.

    **This must never be used for rule matching.** Resolving `..` turns
    `../../etc/passwd` into `/etc/passwd`, and the `path_traversal` rule matches
    on the `..` itself — routing `path_decoded` through here would stop it
    firing entirely. Counting and matching want opposite things from a path: one
    wants the destination, the other wants the journey. Hence a separate
    function rather than another step in `normalize`.

    Percent-decoding is deliberately not done here. `/%61dmin` and `/admin` are
    also one resource, but folding them together is a wider change to what a
    path count means, and it belongs with its own measurement rather than
    smuggled in beside a structural fix.

    Case is preserved: `/Admin` and `/admin` are different resources on any
    case-sensitive server, and treating them as one would undercount real
    enumeration.
    """
    if not path:
        return ""

    leading = path.startswith("/")
    resolved: list[str] = []
    for segment in path.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            # Clamped at the root rather than allowed to escape: what a
            # traversal was *reaching for* is a matching question, and matching
            # sees the raw path anyway.
            if resolved:
                resolved.pop()
            continue
        resolved.append(segment)

    joined = "/".join(resolved)
    return f"/{joined}" if leading else joined
