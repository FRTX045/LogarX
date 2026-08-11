"""Which CRS attack families may name an activity, and which may not.

CRS emits rule IDs and tags; this tool's graph is built from `ActivityCategory`,
and there is no agreed correspondence between the two. ADR-0007 refused to build
one for *scoring*, and that refusal stands: a metric resting on a contestable
mapping turns every taxonomy change into an apparent regression.

This table exists for a narrower job. A CRS detection may name a request's
category **only where the rules packed here reached INFO** — either nothing
matched at all, or the only thing that matched was an observation like
`Scripted Client`, which notices a `curl` user-agent without claiming an attack.
Anything LOW or above is a real claim about the request and wins outright.

So an entry here can never overwrite a label a rule asserted; it can only
replace a non-answer. That bound is what makes the table defensible where a
general mapping would not be.

Every entry is an opinion. They are written out one per line, with the reason,
so they can be argued with rather than inherited.
"""

from __future__ import annotations

from typing import Final

from logarc.core.activity import ActivityCategory, Severity

__all__ = [
    "KNOWN_FAMILIES",
    "RESCUE_CONFIDENCE",
    "category_for_family",
    "severity_for",
]

#: How sure a rescued label is allowed to be.
#:
#: Below every hostile native rule in the bundled packs, the lowest of which sits
#: at 0.5 and means something different: that rule looked at the request and
#: asserted a category. A rescue infers the category from a family tag through
#: the table below, which is one more step of judgement and should read as less
#: certain wherever the two appear side by side.
RESCUE_CONFIDENCE: Final = 0.6

_FAMILY_CATEGORY: Final[dict[str, ActivityCategory]] = {
    # Payload injected into a query the server then executes or renders. All of
    # these are `injection` in this taxonomy because the taxonomy names observed
    # behaviour, not the vulnerability class the payload exploits.
    "attack-sqli": ActivityCategory.INJECTION,
    "attack-xss": ActivityCategory.INJECTION,
    "attack-injection-generic": ActivityCategory.INJECTION,
    "attack-injection-php": ActivityCategory.INJECTION,
    "attack-ssti": ActivityCategory.INJECTION,
    # 944. `injection` rather than `exploitation` even though the bundled
    # `log4shell_jndi` rule calls it the latter, because 944's other thirteen
    # rules are tagged `attack-rce` and land on `injection`. Splitting one
    # family across two categories would fragment an episode on which of its
    # rules happened to fire; where `log4shell_jndi` matches it is CRITICAL and
    # wins outright anyway, so this only governs what CRS alone caught.
    "attack-injection-java": ActivityCategory.INJECTION,
    # Command execution. `injection` rather than `exploitation` so this agrees
    # with the bundled `command_injection` rule, which is categorised that way
    # already. A mapping that invented a second answer for the same behaviour
    # would split episodes on where a detection happened to come from.
    "attack-rce": ActivityCategory.INJECTION,
    # Local file inclusion is reading a path the application did not intend to
    # expose, which is what `path_traversal` names.
    "attack-lfi": ActivityCategory.PATH_TRAVERSAL,
    # Remote inclusion and SSRF are both "make the server fetch something for
    # me". The bundled 931 detections already reach `ssrf`.
    "attack-rfi": ActivityCategory.SSRF,
    "attack-ssrf": ActivityCategory.SSRF,
    # A named scanner announcing itself. Behaviourally this is someone looking
    # around, which is what the bundled `scanner_user_agent` rule calls it.
    "attack-reputation-scanner": ActivityCategory.RECONNAISSANCE,
    # Session fixation: forcing a session identifier is an attack on who the
    # application thinks you are.
    "attack-fixation": ActivityCategory.ACCESS_CONTROL,
}

#: Families that are recorded as evidence but may never name an activity.
#:
#: Not an oversight and not a to-do list. Each is here because letting it
#: override `browsing` would be worse than leaving the request alone:
#:
#: - `attack-protocol` is the largest group in the request rules (920/921) and
#:   the least behavioural. It fires on request lines that are unusual rather
#:   than hostile — an odd encoding, a missing header, a nonstandard method —
#:   and mapping it would turn ordinary traffic hostile in bulk.
#: - `attack-multipart-header` concerns request bodies, which an access log
#:   never has.
#: - `attack-deprecated-header` is retained-for-compatibility rules CRS itself
#:   no longer stands behind.
#: - `attack-generic` reads like a catch-all for 934 and is nothing of the kind:
#:   it belongs to 905 (common exceptions) and rule 911100, "Method is not
#:   allowed by policy". Mapping it to `injection` was wrong and real traffic
#:   caught it — 365 lines of 2010 WordPress logs produced seven 911100 matches
#:   on `CONNECT` proxy abuse, every one of which would have been reported as an
#:   injection. 934's own payloads carry `attack-injection-generic` and are
#:   mapped above. The proxy abuse is real signal and deserves a native rule
#:   that names it correctly, rather than a borrowed category that does not.
_UNMAPPED: Final[frozenset[str]] = frozenset(
    {
        "attack-protocol",
        "attack-multipart-header",
        "attack-deprecated-header",
        "attack-generic",
    }
)

#: Every `attack-*` tag the pinned ruleset's REQUEST rules carry.
#:
#: Held here so a test can assert the two sets above account for all of it. The
#: first draft of this table was written from a grep that truncated at the
#: hyphen, so `attack-injection-php` was silently absent and every PHP payload
#: went unrescued while appearing to work. A version bump that adds a tag should
#: fail a test, not quietly narrow coverage.
KNOWN_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "attack-deprecated-header",
        "attack-fixation",
        "attack-generic",
        "attack-injection-generic",
        "attack-injection-java",
        "attack-injection-php",
        "attack-lfi",
        "attack-multipart-header",
        "attack-protocol",
        "attack-rce",
        "attack-reputation-scanner",
        "attack-rfi",
        "attack-sqli",
        "attack-ssrf",
        "attack-ssti",
        "attack-xss",
    }
)

#: CRS severity words to this tool's ladder. CRS has no INFO level; NOTICE is
#: its floor for a reportable rule.
_SEVERITY: Final[dict[str, Severity]] = {
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
}


def category_for_family(family: str | None) -> ActivityCategory | None:
    """The category a detection from `family` may name, or None.

    None is the ordinary answer for anything not in the table — an unrecognised
    or deliberately withheld family is a request this tool has no opinion about,
    not an error. New CRS releases add tags, and a version bump must not become
    a crash.
    """
    if family is None or family in _UNMAPPED:
        return None
    return _FAMILY_CATEGORY.get(family)


def severity_for(severity: str | None) -> Severity:
    """Read CRS's severity word onto this tool's ladder.

    Unknown words fall to MEDIUM rather than to the floor: a rule severe enough
    to carry a message and reach here is not INFO, and guessing downwards would
    hide it beneath the benign classifications.
    """
    if severity is None:
        return Severity.MEDIUM
    return _SEVERITY.get(severity.strip().lower(), Severity.MEDIUM)
