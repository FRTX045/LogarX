"""The rule model and its YAML loader.

Rule packs are edited by hand, so validation errors have to be useful: which
rule, which field, and what was expected. A stack trace out of a regex compiler
is not an acceptable answer to a typo in a data file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from logarc.core.activity import ActivityCategory, Severity

__all__ = [
    "MATCH_FIELDS",
    "WINDOW_METRICS",
    "Condition",
    "Rule",
    "RulePackError",
    "SequenceRule",
    "SignatureRule",
    "WindowRule",
    "load_pack_text",
    "load_rules",
]


class RulePackError(ValueError):
    """Raised when a rule pack cannot be loaded or is invalid.

    Carries where, as well as what, for the screen that has to point at the
    mistake: the rule's id, the path to the condition inside it as the validator
    gave it, or the line when the YAML itself would not read. The message stays
    the whole sentence, for the command line; `reason` is the part after the
    place, for a screen that says the place its own way.
    """

    def __init__(
        self,
        message: str,
        *,
        rule_id: str | None = None,
        location: tuple[str | int, ...] = (),
        line: int | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.rule_id = rule_id
        self.location = location
        self.line = line
        self.reason = reason if reason is not None else message


#: Text fields a signature rule may match against. `*_decoded` variants have
#: been through evasion normalisation; the raw forms are kept so a rule can
#: deliberately target what was literally sent.
MATCH_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "method",
        "path",
        "query",
        "target",
        "referer",
        "user_agent",
        "protocol",
        "host",
        "extension",
        "path_decoded",
        "query_decoded",
        "target_decoded",
        "referer_decoded",
        "user_agent_decoded",
        "status",
        "bytes_sent",
        "decode_depth",
        "had_null",
        "referer_offsite",
        "query_url_offsite",
    }
)

#: Metrics a window rule may test. These are the things that only become
#: visible across several requests, which is exactly what a signature cannot see.
WINDOW_METRICS: Final[frozenset[str]] = frozenset(
    {
        "request_count",
        "distinct_paths",
        "distinct_methods",
        "not_found_ratio",
        "client_error_ratio",
        "server_error_ratio",
        "success_ratio",
        "distinct_statuses",
        "requests_per_second",
        "static_asset_ratio",
    }
)

_OPERATORS: Final[frozenset[str]] = frozenset({">=", ">", "<=", "<", "==", "!="})


class Condition(BaseModel):
    """One test against a single field of a request."""

    model_config = ConfigDict(extra="forbid")

    field_name: Annotated[str, Field(alias="field")]
    regex: str | None = None
    contains: str | None = None
    equals: str | None = None
    any_of: list[str] | None = None
    min: float | None = None
    max: float | None = None

    @field_validator("field_name")
    @classmethod
    def _known_field(cls, value: str) -> str:
        if value not in MATCH_FIELDS:
            options = ", ".join(sorted(MATCH_FIELDS))
            raise ValueError(f"unknown match field {value!r}; available fields are: {options}")
        return value

    @model_validator(mode="after")
    def _exactly_one_predicate(self) -> Condition:
        predicates = [self.regex, self.contains, self.equals, self.any_of, self.min, self.max]
        if sum(predicate is not None for predicate in predicates) != 1:
            raise ValueError(
                "a condition needs exactly one of: regex, contains, equals, any_of, min, max"
            )
        return self

    _pattern: re.Pattern[str] | None = PrivateAttr(default=None)
    """Compiled at load time so matching does not recompile per request.

    Held as a private attribute rather than in a side table keyed by `id()`:
    CPython reuses ids after garbage collection, so such a table can hand one
    condition another's pattern once the original is freed.
    """

    @property
    def compiled(self) -> re.Pattern[str] | None:
        return self._pattern

    def compile(self) -> None:
        """Compile the pattern once, at load time rather than per request."""
        if self.regex is not None:
            self._pattern = re.compile(self.regex, re.IGNORECASE)


class MatchBlock(BaseModel):
    """Conditions combined with `any` (or) or `all` (and)."""

    model_config = ConfigDict(extra="forbid")

    any: list[Condition] | None = None
    all: list[Condition] | None = None

    @model_validator(mode="after")
    def _one_combinator(self) -> MatchBlock:
        if (self.any is None) == (self.all is None):
            raise ValueError("a match block needs exactly one of: any, all")
        return self

    @property
    def conditions(self) -> list[Condition]:
        return self.any if self.any is not None else (self.all or [])

    @property
    def requires_all(self) -> bool:
        return self.all is not None


class WindowCondition(BaseModel):
    """One threshold on a windowed metric."""

    model_config = ConfigDict(extra="forbid")

    metric: str
    op: str
    value: float

    @field_validator("metric")
    @classmethod
    def _known_metric(cls, value: str) -> str:
        if value not in WINDOW_METRICS:
            options = ", ".join(sorted(WINDOW_METRICS))
            raise ValueError(f"unknown window metric {value!r}; available metrics are: {options}")
        return value

    @field_validator("op")
    @classmethod
    def _known_operator(cls, value: str) -> str:
        if value not in _OPERATORS:
            raise ValueError(f"unknown operator {value!r}; use one of {', '.join(_OPERATORS)}")
        return value


class WindowBlock(BaseModel):
    """A sliding window and the thresholds that make it fire."""

    model_config = ConfigDict(extra="forbid")

    span_seconds: Annotated[int, Field(gt=0)]
    min_requests: Annotated[int, Field(gt=0)] = 1
    conditions: Annotated[list[WindowCondition], Field(min_length=1)]


class _RuleBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: ActivityCategory
    severity: Severity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    owasp: str | None = None
    references: tuple[str, ...] = ()
    icon: str | None = None
    """What the window draws for an activity this rule names: a Lucide name or
    `file:` and an image in the reader's icons folder. Presentation only, so it
    is left out of `RuleEngine.fingerprint`, and a name nothing answers to is
    the window's note to make, not a reason to refuse the pack."""
    source_pack: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, value: object) -> object:
        return Severity.parse(value) if isinstance(value, str) else value


class SignatureRule(_RuleBase):
    """Fires on a single request matching a pattern."""

    match: MatchBlock

    def compile(self) -> None:
        for condition in self.match.conditions:
            condition.compile()


class WindowRule(_RuleBase):
    """Fires on a run of requests whose aggregate behaviour crosses a threshold.

    These catch what no single request reveals: twenty 404s in a minute is
    enumeration, while any one of them is just a missing page.
    """

    window: WindowBlock
    member: MatchBlock | None = None
    """Which requests the rule is about.

    Without it, a window is just a span of time, and a burst of 404s next to a
    stretch of ordinary browsing produces a window straddling both — labelling
    the browsing as enumeration. With it, metrics are computed over matching
    requests only, and only those are labelled. The window then describes a
    behaviour rather than a period.
    """
    outranks: tuple[ActivityCategory, ...] = ()
    """Categories this rule's label leads over on the requests it labels, whatever
    their severity. A sweep of misses that counts `/.env` among them is a wordlist
    with `/.env` in it: the probe rule says what the request was, the sweep what
    the client was doing. Only on the window's own requests, and only the
    categories named; an attack inside the sweep still leads."""

    @model_validator(mode="after")
    def _not_itself(self) -> WindowRule:
        if self.category in self.outranks:
            raise ValueError("a window rule outranks its own category, which sets its label aside")
        return self

    def compile(self) -> None:
        if self.member is not None:
            for condition in self.member.conditions:
                condition.compile()


class SequenceBlock(BaseModel):
    """One request, then another within a time, unless a third came between."""

    model_config = ConfigDict(extra="forbid")

    within_seconds: Annotated[int, Field(gt=0)]
    first: MatchBlock
    then: MatchBlock
    unless_between: MatchBlock | None = None
    first_at_least: Annotated[int, Field(gt=0)] = 1
    """How many `first` requests must be held, inside `within_seconds`, when `then`
    arrives. One is a sequence; five refused sign-ins and then an accepted one is
    a count that only order can say."""
    closes: Literal["all", "last"] = "all"
    """Which held `first` requests `then` labels: every one inside the window, or
    only the latest. `last` is the request just before: of three admin pages and
    then a sign-in asking to go back to the admin area, only the third asked for
    the sign-in, and the two before it were ordinary use."""

    def blocks(self) -> list[MatchBlock]:
        return [self.first, self.then, *([self.unless_between] if self.unless_between else [])]


class SequenceRule(_RuleBase):
    """Fires when one request follows another, with nothing that explains it between.

    For what neither a single request nor a count can say. An administrator and
    an intruder can both be bounced from `/admin/` to the login page and both be
    let in to an admin page a minute later; what separates them is whether a
    sign-in came between, which is order, not quantity. Both ends of a sequence
    are labelled, and nothing else is.
    """

    sequence: SequenceBlock

    def compile(self) -> None:
        for block in self.sequence.blocks():
            for condition in block.conditions:
                condition.compile()


Rule = SignatureRule | WindowRule | SequenceRule


class _RulePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    note: str | None = None
    """What the pack is for, in its author's words. Shown beside its name."""
    rules: list[dict[str, Any]] = []

    @field_validator("rules", mode="before")
    @classmethod
    def _none_yet(cls, value: object) -> object:
        # `rules:` with only comments under it is YAML for null: a pack with no
        # rules yet, which is how a new one starts.
        return [] if value is None else value


def load_rules(sources: list[Path]) -> list[Rule]:
    """Load rules from YAML files and directories of YAML files."""
    rules: list[Rule] = []
    seen: dict[str, str] = {}

    for path in _expand(sources):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RulePackError(f"{path.name} could not be read: {exc}") from exc
        for rule in load_pack_text(path.name, text):
            if rule.id in seen:
                raise RulePackError(
                    f"duplicate rule id {rule.id!r} in {path.name}; "
                    f"already defined in {seen[rule.id]}",
                    rule_id=rule.id,
                )
            seen[rule.id] = path.name
            rules.append(rule)
    return rules


def load_pack_text(name: str, text: str) -> list[Rule]:
    """One pack's rules from its YAML.

    `name` is what a message calls the pack and what each rule records as the
    pack it came from — the file name, `shopfront.yaml`. The one loader behind
    both the files the command line is given and the text the window holds, so
    the two cannot read the same pack differently.
    """
    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in _parse_pack(name, text):
        rule = _build_rule(raw, name)
        if rule.id in seen:
            raise RulePackError(
                f"duplicate rule id {rule.id!r} in {name}; already defined in {name}",
                rule_id=rule.id,
                reason="another rule in this pack already has this id",
            )
        seen.add(rule.id)
        rule.compile()
        rules.append(rule)
    return rules


def _expand(sources: list[Path]) -> list[Path]:
    """Every pack file under the given files and directories.

    Directories are searched all the way down, because the bundled packs are
    grouped into folders (`attack/php.yaml`, `action/global.yaml`), and so
    is any collection large enough to want organising. A one-level search read
    a grouped directory as empty and returned no rules, without an error: the
    tool then analysed the case with its detection layer quietly absent, which
    is the one failure this project treats as worse than crashing.

    An empty directory is refused for the same reason. Zero rules is not an
    answer, and a mistyped path or a `.yml` spelling produces exactly that.
    """
    paths: list[Path] = []
    for source in sources:
        source = Path(source)
        if source.is_dir():
            found = sorted(source.rglob("*.yaml"))
            if not found:
                raise RulePackError(
                    f"no rule packs under {source}. Rule packs are YAML files "
                    f"ending in .yaml, and subdirectories are searched too."
                )
            paths.extend(found)
        elif source.exists():
            paths.append(source)
        else:
            raise RulePackError(f"rule pack not found: {source}")
    return paths


def _parse_pack(name: str, text: str) -> list[dict[str, Any]]:
    try:
        payload = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise RulePackError(
            f"{name} could not be read: {exc}",
            line=_yaml_line(exc),
            reason=getattr(exc, "problem", None) or str(exc),
        ) from exc

    try:
        pack = _RulePack.model_validate(payload)
    except ValidationError as exc:
        raise RulePackError(
            f"{name} is not a valid rule pack: {_first_problem(exc)}",
            location=_location(exc),
            reason=_reason(exc),
        ) from exc
    return pack.rules


def _yaml_line(exc: yaml.YAMLError) -> int | None:
    """The line a reader has to change, counted from one.

    PyYAML has two marks. For a missing colon it reports the line after, where
    it was still looking for one, and for an unclosed brace the line where the
    next one opens; the line at fault is the one the context mark names.
    Elsewhere the problem mark is the place.
    """
    context = getattr(exc, "context", None) or ""
    mark = None
    if "simple key" in context or "flow" in context:
        mark = getattr(exc, "context_mark", None)
    mark = mark or getattr(exc, "problem_mark", None)
    return mark.line + 1 if mark is not None else None


def _build_rule(raw: dict[str, Any], name: str) -> Rule:
    label = raw.get("id", "<unnamed>")
    rule_id = label if isinstance(label, str) else None
    body = {**raw, "source_pack": name}

    kinds = [kind for kind in _KINDS if kind in body]
    if len(kinds) != 1:
        raise RulePackError(
            f"rule {label!r} in {name} must have exactly one of: {', '.join(_KINDS)}",
            rule_id=rule_id,
            reason=f"a rule needs exactly one of: {', '.join(_KINDS)}",
        )

    model = _KINDS[kinds[0]]
    try:
        rule = model.model_validate(body)
    except ValidationError as exc:
        raise RulePackError(
            f"rule {label!r} in {name}: {_first_problem(exc)}",
            rule_id=rule_id,
            location=_location(exc),
            reason=_reason(exc),
        ) from exc

    if isinstance(rule, SignatureRule):
        _check_patterns(rule.id, rule.match, name, ("match",))
    elif isinstance(rule, SequenceRule):
        for part in ("first", "then", "unless_between"):
            block = getattr(rule.sequence, part)
            if block is not None:
                _check_patterns(rule.id, block, name, ("sequence", part))
    return rule


#: The body that says what kind of rule a pack entry is, and the model for it.
_KINDS: Final[dict[str, type[Rule]]] = {
    "match": SignatureRule,
    "window": WindowRule,
    "sequence": SequenceRule,
}


def _check_patterns(rule_id: str, block: MatchBlock, name: str, at: tuple[str | int, ...]) -> None:
    combinator = "all" if block.requires_all else "any"
    for index, condition in enumerate(block.conditions):
        if condition.regex is None:
            continue
        try:
            re.compile(condition.regex)
        except re.error as exc:
            raise RulePackError(
                f"rule {rule_id!r} in {name}: invalid regex {condition.regex!r}: {exc}",
                rule_id=rule_id,
                location=(*at, combinator, index),
                reason=f"the pattern {condition.regex!r} is not a valid regular expression: {exc}",
            ) from exc


def _first_problem(exc: ValidationError) -> str:
    location = ".".join(str(part) for part in _location(exc)) or "rule"
    return f"{location}: {_reason(exc)}"


def _location(exc: ValidationError) -> tuple[str | int, ...]:
    return tuple(exc.errors()[0]["loc"])


def _reason(exc: ValidationError) -> str:
    # Pydantic puts the kind of error in front of a validator's own message.
    # "Value error" names a class in a library, nothing a pack's author can act on.
    return str(exc.errors()[0]["msg"]).removeprefix("Value error, ")
