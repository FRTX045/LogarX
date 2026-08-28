"""A log format written down as data, rather than held only as a parser.

Three things need a log format and none of them can be handed a live object.
A worker started by spawn is reached through pickle; a case is written to JSON
and read back years later; a saved format sits in a file between runs. Passing
the format's *name* solves none of them, because a name only works where the
definition behind it is already known — which is exactly what stops being true
once users can write their own.

So a format is a record, and the parser is built from the record. That reverses
the dependency: `LogFormatSpec` is primary and `LogFormatParser` is derived.

Loading is deliberately not compiling. `spec_from_dict` accepts a definition it
cannot build a parser from, and `build()` is where that fails — because a case
stores the definition it was ingested with, and a stored definition that could
refuse to *load* would take the whole case down over one broken format. Today
an unresolvable format leaves the line text readable and only its fields
missing (see `evidence._parser_for`); that stays true.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any, ClassVar, Final

from logarc.parsers.logformat import LogFormatParser

if TYPE_CHECKING:
    from collections.abc import Mapping

    from logarc.parsers.base import LogParser

__all__ = [
    "SPEC_VERSION",
    "FormatSpec",
    "FormatSpecError",
    "LogFormatSpec",
    "spec_from_dict",
    "spec_to_dict",
]

#: Bumped when a written definition changes shape. A case keeps its definition
#: indefinitely, so a later logarc must either read this one or say plainly that
#: it cannot — silently misreading it would be the worse of the two.
SPEC_VERSION: Final = 1


class FormatSpecError(ValueError):
    """Raised when a stored format definition cannot be read back."""


@dataclass(frozen=True, slots=True)
class LogFormatSpec:
    """An Apache-style `LogFormat` directive, named.

    Frozen and slotted so it can be pickled to a worker without carrying a
    dictionary, and compared by value — which is what the drift check between a
    case's copy and the saved library entry relies on.
    """

    #: The tag written into JSON. Later kinds (`json`, `columns`, `pattern`)
    #: take their own, and a reader dispatches on it.
    kind: ClassVar[str] = "logformat"

    name: str
    directive: str
    description: str = ""

    def build(self) -> LogParser:
        """Compile this definition into a parser.

        Raises `LogFormatError` for a directive that will not compile. That is
        the only place a bad definition is allowed to fail; see the module
        docstring for why loading one must not.
        """
        return LogFormatParser(self.directive, name=self.name)


#: The union of every kind. One member today; the tagged dispatch below is what
#: lets a second be added without changing anything already written to a case.
FormatSpec = LogFormatSpec

_KINDS: Final[dict[str, type[FormatSpec]]] = {LogFormatSpec.kind: LogFormatSpec}


def spec_to_dict(spec: FormatSpec) -> dict[str, Any]:
    """Render a spec as the JSON object a case or a library file stores."""
    payload: dict[str, Any] = {"version": SPEC_VERSION, "kind": spec.kind}
    for entry in fields(spec):
        payload[entry.name] = getattr(spec, entry.name)
    return payload


def spec_from_dict(payload: Mapping[str, Any]) -> FormatSpec:
    """Read back a stored definition, or say precisely why it cannot be read."""
    version = payload.get("version")
    if not isinstance(version, int):
        raise FormatSpecError(f"format definition has no usable 'version': {version!r}")
    if version > SPEC_VERSION:
        raise FormatSpecError(
            f"format definition is version {version}, and this logarc reads up to "
            f"version {SPEC_VERSION}; it was written by a newer logarc"
        )

    kind = payload.get("kind")
    spec_type = _KINDS.get(kind) if isinstance(kind, str) else None
    if spec_type is None:
        known = ", ".join(sorted(_KINDS))
        raise FormatSpecError(f"unknown format 'kind' {kind!r}; this logarc reads: {known}")

    # Unknown keys are refused rather than ignored. The library file is plain
    # JSON that a user may edit by hand, and a misspelt key accepted in silence
    # would drop whatever they were trying to set while appearing to work.
    expected = {entry.name for entry in fields(spec_type)}
    if unexpected := sorted(set(payload) - expected - {"version", "kind"}):
        raise FormatSpecError(
            f"format definition has fields a {kind!r} format does not use: "
            f"{', '.join(repr(name) for name in unexpected)}"
        )

    try:
        return spec_type(**{name: payload[name] for name in expected if name in payload})
    except TypeError as exc:  # a required field is absent
        raise FormatSpecError(f"format definition is incomplete: {exc}") from exc
