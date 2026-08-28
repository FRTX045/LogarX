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

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Final

from logarc.parsers.json_format import JsonParser
from logarc.parsers.logformat import LogFormatParser

if TYPE_CHECKING:
    from collections.abc import Mapping

    from logarc.parsers.base import LogParser

__all__ = [
    "SPEC_VERSION",
    "FormatSpec",
    "FormatSpecError",
    "JsonFormatSpec",
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

    #: What `to_payload` writes. See `JsonFormatSpec.PAYLOAD_KEYS`.
    PAYLOAD_KEYS: ClassVar[frozenset[str]] = frozenset({"name", "directive", "description"})

    name: str
    directive: str
    description: str = ""

    @property
    def summary(self) -> str:
        """One line naming what this format actually is, for a list of them.

        Separate from `description`, which is whatever note the user wrote.
        Later kinds have no directive to show and give their own summary, so a
        caller displaying a format never has to know which kind it holds.
        """
        return self.directive

    def build(self) -> LogParser:
        """Compile this definition into a parser.

        Raises `LogFormatError` for a directive that will not compile. That is
        the only place a bad definition is allowed to fail; see the module
        docstring for why loading one must not.
        """
        return LogFormatParser(self.directive, name=self.name)

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "directive": self.directive,
            "description": self.description,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> LogFormatSpec:
        return cls(
            name=_text(payload, "name"),
            directive=_text(payload, "directive"),
            description=_text(payload, "description", required=False),
        )


@dataclass(frozen=True, slots=True)
class JsonFormatSpec:
    """One JSON object per line, with a mapping from our field names to theirs.

    The mapping is held as pairs rather than a dictionary so the record really
    is frozen — a dictionary attribute can be reassigned nowhere and mutated
    anywhere, which for a definition a case stores forever is the wrong kind of
    immutable. It is written to JSON as an object all the same, because the
    library file is meant to be openable in an editor and a list of pairs is
    not.
    """

    kind: ClassVar[str] = "json"

    #: What `to_payload` writes, so a hand-edited file can be checked against
    #: it. Declared rather than derived from the dataclass: the two differ by
    #: design, and deriving one from the other would tie the file's shape to
    #: the class's, which is the coupling `to_payload` exists to break.
    PAYLOAD_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"name", "fields", "time_format", "description"}
    )

    name: str
    fields: tuple[tuple[str, str], ...]
    """Our field name, then the key in their log. Order is the reader's."""

    time_format: str = ""
    """A strftime pattern, when the timestamp is in neither ISO nor epoch."""

    description: str = ""

    @property
    def summary(self) -> str:
        """The mapping on one line, for a list of formats."""
        return ", ".join(f"{ours}={theirs}" for ours, theirs in self.fields)

    def build(self) -> LogParser:
        """Build the parser, or refuse the mapping and say why.

        Refused here rather than at ingest, where a mapping missing its
        timestamp would quarantine every line of the log and present as an
        empty case.
        """
        return JsonParser(self.fields, name=self.name, time_format=self.time_format)

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fields": dict(self.fields),
            "time_format": self.time_format,
            "description": self.description,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> JsonFormatSpec:
        mapping = payload.get("fields")
        if not isinstance(mapping, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in mapping.items()
        ):
            raise FormatSpecError("a json format's 'fields' must map names to keys")
        return cls(
            name=_text(payload, "name"),
            fields=tuple(mapping.items()),
            time_format=_text(payload, "time_format", required=False),
            description=_text(payload, "description", required=False),
        )


def _text(payload: Mapping[str, Any], key: str, *, required: bool = True) -> str:
    value = payload.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise FormatSpecError(f"format definition needs {key!r} to be text, not {value!r}")
    return value


#: The union of every kind. The tagged dispatch below is what lets a third be
#: added without changing anything already written to a case.
FormatSpec = LogFormatSpec | JsonFormatSpec

_KINDS: Final[dict[str, type[FormatSpec]]] = {
    LogFormatSpec.kind: LogFormatSpec,
    JsonFormatSpec.kind: JsonFormatSpec,
}


def spec_to_dict(spec: FormatSpec) -> dict[str, Any]:
    """Render a spec as the JSON object a case or a library file stores.

    The shape is the kind's own, not the dataclass's: a mapping held as pairs
    in memory is still written as an object, because a person opens this file.
    """
    return {"version": SPEC_VERSION, "kind": spec.kind, **spec.to_payload()}


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
    expected = spec_type.PAYLOAD_KEYS
    if unexpected := sorted(set(payload) - expected - {"version", "kind"}):
        raise FormatSpecError(
            f"format definition has fields a {kind!r} format does not use: "
            f"{', '.join(repr(name) for name in unexpected)}"
        )

    return spec_type.from_payload(payload)
