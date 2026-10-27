"""An nginx `log_format`, read as the Apache directive it means.

Sites customise nginx's log format more than any other server's, and the
reader should not have to translate `$variables` into `%` directives by hand: a
wrong hand translation reads as a format that does not match, or worse, as one
that matches and reads the wrong field. So `LogFormatParser` hands nginx text
here and compiles what comes back, and the format keeps the text exactly as the
reader pasted it.

What is pasted can be the whole statement as nginx's config holds it,
`log_format main '...' '...';`, its quoted strings alone, or the format itself.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = ["NginxFormatError", "looks_like_nginx", "to_directive"]


class NginxFormatError(ValueError):
    """Raised when nginx text cannot be read as a log format, saying why."""


#: `$name` or `${name}`. nginx takes the longest run of name characters.
_VARIABLE: Final = re.compile(r"\$(?:\{(?P<braced>[A-Za-z0-9_]+)\}|(?P<bare>[A-Za-z0-9_]+))")

#: An Apache directive, as `logformat` reads one (`%%` aside). Text with one of
#: these is Apache's, whatever else it holds.
_DIRECTIVE: Final = re.compile(r"%[!0-9,]*[<>]?(?:\{[^}]*\}[a-zA-Z]|[a-zA-Z])")

_STATEMENT: Final = re.compile(r"\s*log_format(?:\s|$)")

#: Variables with an Apache directive of their own. The ones not here and not
#: a header or a cookie are kept beside the event as `%{name}e`, which is how
#: the `ingress-nginx` built-in keeps nginx's upstream fields.
_DIRECTIVES: Final[dict[str, str]] = {
    "remote_addr": "%h",
    "remote_user": "%u",
    "time_local": "%{%d/%b/%Y:%H:%M:%S %z}t",
    "time_iso8601": "%{%Y-%m-%dT%H:%M:%S%z}t",
    "request": "%r",
    "request_method": "%m",
    # The path and the query as sent; `logformat` splits a path at `?`.
    "request_uri": "%U",
    "uri": "%U",
    "document_uri": "%U",
    "args": "%q",
    "query_string": "%q",
    "server_protocol": "%H",
    "status": "%>s",
    "body_bytes_sent": "%b",
    "bytes_sent": "%O",
    "request_length": "%I",
    "request_time": "%T",
    "host": "%v",
    "http_host": "%v",
    "server_name": "%v",
    "server_addr": "%A",
    "server_port": "%p",
    "pid": "%P",
}

_TIMES: Final[frozenset[str]] = frozenset({"time_local", "time_iso8601"})

#: nginx's config reader turns these back into what they stand for inside a
#: quoted string; any other backslash stays as written.
_CONFIG_ESCAPES: Final[dict[str, str]] = {
    '"': '"',
    "'": "'",
    "\\": "\\",
    "t": "\t",
    "r": "\r",
    "n": "\n",
}


def looks_like_nginx(text: str) -> bool:
    """Whether `text` is an nginx log format rather than an Apache directive.

    A `log_format` statement is, and so is text with `$variables` and no `%`
    directive. Every Apache format has a directive, so nothing read as Apache
    before is read differently now; text with both is Apache's.
    """
    if _STATEMENT.match(text):
        return True
    return _VARIABLE.search(text) is not None and _DIRECTIVE.search(text) is None


def _config_tokens(text: str) -> list[tuple[str, bool]]:
    """Split text the way nginx's config reader does: words and quoted strings,
    up to a `;`, with `#` starting a comment. Each token says whether it was
    quoted."""
    tokens: list[tuple[str, bool]] = []
    index, end = 0, len(text)
    while index < end:
        char = text[index]
        if char.isspace():
            index += 1
        elif char == "#":
            newline = text.find("\n", index)
            index = end if newline < 0 else newline
        elif char == ";":
            break
        elif char in "'\"":
            quote, index, value = char, index + 1, []
            while index < end and text[index] != quote:
                if text[index] == "\\" and index + 1 < end:
                    following = text[index + 1]
                    value.append(_CONFIG_ESCAPES.get(following, "\\" + following))
                    index += 2
                else:
                    value.append(text[index])
                    index += 1
            if index >= end:
                raise NginxFormatError(f"a string opened with {quote} is never closed")
            tokens.append(("".join(value), True))
            index += 1
        else:
            start = index
            while index < end and not text[index].isspace() and text[index] not in ";#":
                index += 1
            tokens.append((text[start:index], False))
    return tokens


def _format_of(text: str) -> tuple[str, str]:
    """The format itself and its `escape=` setting, from whatever was pasted."""
    stripped = text.strip()
    if _STATEMENT.match(stripped):
        tokens = [value for value, _quoted in _config_tokens(stripped)][1:]
        if not tokens:
            raise NginxFormatError("a log_format statement needs a name and a format")
        rest = tokens[1:]
        escape = "default"
        if rest and rest[0].startswith("escape="):
            escape, rest = rest[0].removeprefix("escape="), rest[1:]
        if not rest:
            raise NginxFormatError(f"log_format {tokens[0]} has no format after its name")
        return "".join(rest), escape
    if stripped[:1] in ("'", '"'):
        # Quoted strings alone, as copied from a config: only when every piece
        # is one. A format of the site's own may start with a quote of its own.
        try:
            pieces = _config_tokens(stripped)
        except NginxFormatError:
            pieces = []
        if pieces and all(quoted for _value, quoted in pieces):
            return "".join(value for value, _quoted in pieces), "default"
    return stripped, "default"


def _directive(name: str) -> str:
    if (known := _DIRECTIVES.get(name)) is not None:
        return known
    if name.startswith("sent_http_"):
        return "%{" + name.removeprefix("sent_http_").replace("_", "-") + "}o"
    if name.startswith("http_"):
        return "%{" + name.removeprefix("http_").replace("_", "-") + "}i"
    if name.startswith("cookie_"):
        return "%{" + name.removeprefix("cookie_") + "}C"
    return "%{" + name + "}e"


def to_directive(text: str) -> str:
    """The Apache directive that reads what an nginx format writes.

    Refuses, saying what to do instead, a format whose log is JSON (the JSON
    kind reads it from the log itself), one with nothing to date its events by,
    and one with no `$remote_addr`: a forwarded-for header is the client's own
    to write, and is never the client in a format that could have written the
    connection's address.
    """
    log_format, escape = _format_of(text)
    if escape == "json" or log_format.lstrip().startswith("{"):
        raise NginxFormatError(
            "this nginx format writes JSON. Read its log as a JSON format: "
            "in Case → Formats and rules, New → JSON proposes the mapping from a line of the log"
        )
    if escape not in ("default", "none"):
        raise NginxFormatError(f"escape={escape} is not one nginx knows: default, json or none")

    parts: list[str] = []
    names: set[str] = set()
    position = 0
    for match in _VARIABLE.finditer(log_format):
        name = match["braced"] or match["bare"]
        names.add(name)
        literal = log_format[position : match.start()]
        position = match.end()
        # `[$time_local]` is Apache's `%t`, brackets and all, which keeps the
        # fast path every ordinary line takes.
        if name == "time_local" and literal.endswith("[") and log_format.startswith("]", position):
            parts += [literal[:-1].replace("%", "%%"), "%t"]
            position += 1
            continue
        parts += [literal.replace("%", "%%"), _directive(name)]
    parts.append(log_format[position:].replace("%", "%%"))

    if not names & _TIMES:
        if "msec" in names:
            raise NginxFormatError(
                "this format is dated only by $msec, which logarc does not read yet; "
                "it reads $time_local and $time_iso8601"
            )
        raise NginxFormatError(
            "this format has nothing to date its events by: logarc reads $time_local "
            "and $time_iso8601"
        )
    if "remote_addr" not in names:
        raise NginxFormatError(
            "this format does not write $remote_addr, so it names no client. A "
            "forwarded-for header is the client's own to write, and is not read as one"
        )
    return "".join(parts)
