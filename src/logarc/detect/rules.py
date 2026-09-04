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
    "SignatureRule",
    "WindowRule",
    "load_rules",
]


class RulePackError(ValueError):
    """Raised when a rule pack cannot be loaded or is invalid."""


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
    }
)

#: Metrics a window rule may test. These are the things that only become
#: visible across several requests, which is exactly what a signature cannot see.
WINDOW_METRICS: Final[frozenset[str]] = frozenset(
    {
        "request_count",
        "distinct_paths",
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

    def compile(self) -> None:
        if self.member is not None:
            for condition in self.member.conditions:
                condition.compile()


Rule = SignatureRule | WindowRule


class _RulePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    rules: list[dict[str, Any]] = []


def load_rules(sources: list[Path]) -> list[Rule]:
    """Load rules from YAML files and directories of YAML files."""
    rules: list[Rule] = []
    seen: dict[str, str] = {}

    for path in _expand(sources):
        for raw in _read_pack(path):
            rule = _build_rule(raw, path)
            if rule.id in seen:
                raise RulePackError(
                    f"duplicate rule id {rule.id!r} in {path.name}; "
                    f"already defined in {seen[rule.id]}"
                )
            seen[rule.id] = path.name
            rule.compile()
            rules.append(rule)
    return rules


def _expand(sources: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for source in sources:
        source = Path(source)
        if source.is_dir():
            paths.extend(sorted(source.glob("*.yaml")))
        elif source.exists():
            paths.append(source)
        else:
            raise RulePackError(f"rule pack not found: {source}")
    return paths


def _read_pack(path: Path) -> list[dict[str, Any]]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RulePackError(f"{path.name} could not be read: {exc}") from exc

    try:
        pack = _RulePack.model_validate(payload)
    except ValidationError as exc:
        raise RulePackError(f"{path.name} is not a valid rule pack: {_first_problem(exc)}") from exc
    return pack.rules


def _build_rule(raw: dict[str, Any], path: Path) -> Rule:
    rule_id = raw.get("id", "<unnamed>")
    body = {**raw, "source_pack": path.name}

    has_match, has_window = "match" in body, "window" in body
    if has_match == has_window:
        raise RulePackError(
            f"rule {rule_id!r} in {path.name} must have exactly one of: match, window"
        )

    model: type[Rule] = SignatureRule if has_match else WindowRule
    try:
        rule = model.model_validate(body)
    except ValidationError as exc:
        raise RulePackError(f"rule {rule_id!r} in {path.name}: {_first_problem(exc)}") from exc

    if isinstance(rule, SignatureRule):
        _check_patterns(rule, path)
    return rule


def _check_patterns(rule: SignatureRule, path: Path) -> None:
    for condition in rule.match.conditions:
        if condition.regex is None:
            continue
        try:
            re.compile(condition.regex)
        except re.error as exc:
            raise RulePackError(
                f"rule {rule.id!r} in {path.name}: invalid regex {condition.regex!r}: {exc}"
            ) from exc


def _first_problem(exc: ValidationError) -> str:
    problem = exc.errors()[0]
    location = ".".join(str(part) for part in problem["loc"]) or "rule"
    return f"{location}: {problem['msg']}"
