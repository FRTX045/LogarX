"""The activity taxonomy.

Two layers, deliberately. The **category** is behaviour that can actually be
observed in an access log. The **OWASP mapping** is an attribute hung off that,
not the structure itself.

That way round because OWASP Top 10 classifies vulnerabilities, not behaviour,
and only part of it leaves a trace in a log. Bundled mappings use Top 10:2025:
A01, A02, A03, A05, A07 and A08 are represented, with limited coverage of each.
A08 includes PHP object-injection indicators; A03 covers component-related
indicators, not the whole software supply chain. No bundled mappings claim
A04, A06, A09 or A10. Custom mappings may retain other editions. Structuring
by behaviour keeps the taxonomy independent of these annotations and leaves
room to map onto MITRE ATT&CK or CAPEC without rearranging anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum

__all__ = ["ActivityCategory", "ActivityLabel", "Outcome", "Severity"]


class Severity(IntEnum):
    """How much a finding matters. Ordered so the highest can be selected."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> Severity:
        try:
            return cls[name.strip().upper()]
        except KeyError:
            options = ", ".join(level.name.lower() for level in cls)
            raise ValueError(f"unknown severity {name!r}; choose one of {options}") from None


class ActivityCategory(StrEnum):
    """What a client was doing, as far as the log can show.

    Benign categories are first-class rather than an afterthought: a graph of
    attacks alone loses the thread between them, and cannot distinguish a
    scanner that only ever probed from an attacker who probed, succeeded, and
    then browsed what they had opened.
    """

    # Ordinary use.
    BROWSING = "browsing"
    STATIC_ASSET = "static_asset"
    API_CALL = "api_call"
    AUTHENTICATION = "authentication"
    CRAWLING = "crawling"

    # Attack behaviour.
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    ACCESS_CONTROL = "access_control"
    CREDENTIAL_ATTACK = "credential_attack"
    SSRF = "ssrf"
    EXPLOITATION = "exploitation"

    UNKNOWN = "unknown"

    @property
    def is_hostile(self) -> bool:
        return self in _HOSTILE


_HOSTILE = frozenset(
    {
        ActivityCategory.RECONNAISSANCE,
        ActivityCategory.ENUMERATION,
        ActivityCategory.INJECTION,
        ActivityCategory.PATH_TRAVERSAL,
        ActivityCategory.ACCESS_CONTROL,
        ActivityCategory.CREDENTIAL_ATTACK,
        ActivityCategory.SSRF,
        ActivityCategory.EXPLOITATION,
    }
)


class Outcome(StrEnum):
    """Whether the activity appears to have achieved anything.

    Derived from response codes and sizes. This is the difference between
    "47 injection attempts, all refused" and "47 attempts, three of which
    returned a megabyte" — the same activity, and completely different findings.
    """

    BLOCKED = "blocked"
    """Nothing succeeded: every response was an error."""

    MIXED = "mixed"
    """Some requests succeeded."""

    SUCCESS = "success"
    """Everything succeeded."""

    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ActivityLabel:
    """What a rule concluded about a request."""

    rule_id: str
    name: str
    category: ActivityCategory
    severity: Severity
    confidence: float
    owasp: str | None = None
    references: tuple[str, ...] = ()
