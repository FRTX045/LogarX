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

from zodiarc.core.activity import ActivityCategory, Severity

__all__ = [
    "KNOWN_FAMILIES",
    "RESCUE_CONFIDENCE",
    "category_for",
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

#: Rule ids whose family tag is right about the payload and wrong about the act.
#:
#: `attack-lfi` is the only family so far that needs this, and it needs it
#: because it covers two behaviours that share a mechanism and not a meaning:
#:
#: | rule | message | what it is |
#: |---|---|---|
#: | 930100/930110 | Path Traversal Attack (`/../`) | climbing out of the web root |
#: | 930120/930121 | OS File Access Attempt | reading a system file by name |
#: | 930130 | Restricted File Access Attempt | asking for `/.env`, `/.git/`, `/Dockerfile` |
#: | 930140 | Restricted File Access: AI Coding Assistant Artifact | the same, for newer secrets |
#:
#: The last two are `@pmFromFile` lists of source, manifests, credentials and
#: version-control history — files that are simply *there*, requested by their
#: own name with no traversal at all. That is reconnaissance, and this project
#: already says so: `config_file_exposure` and `backup_file_probe` classify the
#: identical URLs that way. Mapping the whole family to `path_traversal` made
#: CRS contradict the native rule on the same request, and on one labelled
#: corpus produced eight false positives and no true ones.
#:
#: Found the way the other two errors in this file were found — by reading what
#: the rules actually matched, not by reasoning about the tag.
_RULE_CATEGORY: Final[dict[int, ActivityCategory]] = {
    930130: ActivityCategory.RECONNAISSANCE,
    930140: ActivityCategory.RECONNAISSANCE,
}

#: Individual rules that may never name an activity, though their family may.
#:
#: `_UNMAPPED` silences a whole family; this silences one rule inside a family
#: that is otherwise trusted. Both entries were measured on `2026-09-20-medium`,
#: 237,278 requests, by counting what each rule named that nothing else did
#: against what it accused.
#:
#: | rule | CRS calls it | named a real attack | accused ordinary traffic |
#: |---|---|---:|---:|
#: | 932236 | RCE: Unix Command Injection | 0 | 22 |
#:
#: **932236 matches Unix command names with no metacharacter around them**, and
#: on a hardware shop that is the product catalogue: `pipe cutter`, `wall
#: plugs`, `pipe`. `pipe` and `wall` are both shell commands. Third time this
#: project has met the same error — `attack/windows.yaml` exists because `find
#: x for y` and `time warner` are ordinary English, and `http_library_user_agent`
#: was it again in another field. A bare command name is vocabulary, not intent.
#:
#: ## 931100 was in this set for a day, and should not have been
#:
#: It was withheld on 2026-09-22 for accusing 73 ordinary requests against one
#: real catch. Every one of the 73 was the same line:
#:
#:     GET /admin/import-image?url=http://203.0.113.2/assets/img/logo.png
#:
#: **That request was a defect in the corpus, not a mistake by the rule.** The
#: dataset's benign admin step named its own web container by a bridge IP, while
#: every Referer on the same line calls that server `shop.test`. The step exists
#: to be the harmless counterpart of the attackers' metadata-hunting version,
#: and a literal IP in the parameter is the one feature separating those two
#: cases — so the benign example was carrying the hostile marker. CRS 931100
#: fired on it correctly, 73 times. Fixed upstream at `20a4564`.
#:
#: Set those 73 aside and the rule scores 1 for 1 on the same corpus, and on
#: the committed excerpt restoring it is strictly better. So it is restored.
#:
#: **A measurement is evidence about the corpus as much as about the tool.**
#: "This rule has terrible precision" and "this corpus has a mislabelled
#: request" produce the same table. What distinguished them here was reading
#: the 73 and finding they were one line.
_RULE_WITHHELD: Final[frozenset[int]] = frozenset({932236})

#: Rules that are right, and can only be right once CRS knows the site's host.
#:
#: CRS 931130 is "Off-Domain Reference/Link". It decides whether a URL in a
#: parameter is foreign with `!@endsWith .%{request_headers.host}` — against
#: the request's own Host header. Apache does not log that header, so the
#: sidecar synthesises one, and until 2026-09-23 it was always `localhost`:
#: every outbound URL, the site's own asset host included, read as foreign. On
#: 237,278 real requests the rule named 1 genuine attack and accused 73
#: ordinary ones.
#:
#: **An earlier version of this comment said 931130 compares against
#: `TX:ALLOWED_HOSTS`, a list an operator configures.** That was wrong — it was
#: written without reading the rule, repeated in working notes, the ledger and
#: `docs/evaluation.md`, and passed to the dataset project, which repeated it
#: back. The conclusion survived, since the rule was told nothing true about
#: the site either way. The mechanism did not, and the real one is what made
#: the fix small: the sidecar already took a `--host` flag.
#:
#: So `enrich_case` now fills it from the case's `site_hosts`, and this set
#: holds 931130 back only until that has happened. Measured with the sidecar
#: directly — told `shop.test`, the rule is quiet on `shop.test` and
#: `cdn.shop.test` and fires on `evil.test` and on `shop.test.evil.test`, which
#: is the same discrimination `rfi_offsite_url` makes natively.
_NEEDS_SITE_HOST: Final[frozenset[int]] = frozenset({931130})

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


def category_for(
    rule_id: int, family: str | None, *, site_host_known: bool = False
) -> ActivityCategory | None:
    """The category one detection may name, or None.

    `family` decides *whether* a detection may speak; `rule_id` may then correct
    *what* it says. That order is deliberate and is the bound the table has
    always had: an override can redirect a detection the family already allowed,
    and can never give a voice to one the family withheld. Otherwise a listed
    rule id would be a back door for `attack-protocol`.

    `_RULE_WITHHELD` is checked first and is the mirror of that bound: a rule
    silenced by id stays silent whatever its family allows, and it earned the
    place by measurement rather than by argument.

    `site_host_known` is whether CRS was run against a host the reader named.
    It defaults to false, so every caller that does not know reads 931130 as
    withheld — exactly what every caller got before the host could be known.
    """
    if rule_id in _RULE_WITHHELD:
        return None
    if rule_id in _NEEDS_SITE_HOST and not site_host_known:
        return None
    category = category_for_family(family)
    if category is None:
        return None
    return _RULE_CATEGORY.get(rule_id, category)


def severity_for(severity: str | None) -> Severity:
    """Read CRS's severity word onto this tool's ladder.

    Unknown words fall to MEDIUM rather than to the floor: a rule severe enough
    to carry a message and reach here is not INFO, and guessing downwards would
    hide it beneath the benign classifications.
    """
    if severity is None:
        return Severity.MEDIUM
    return _SEVERITY.get(severity.strip().lower(), Severity.MEDIUM)
