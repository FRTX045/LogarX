"""What the Add a rule window says. No Qt.

The labels the form shows for fields, tests and categories, and the sentences
it shows about counts, so they can be checked without a display: the same split
as `gui.rules_view` for the rules tab.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from zodiarc.core.activity import ActivityCategory
from zodiarc.rule_draft import Test
from zodiarc.style import plural

if TYPE_CHECKING:
    from zodiarc.rule_finds import Find

__all__ = [
    "CASE_NOTE",
    "CATEGORY_LABELS",
    "DECODED_TIP",
    "EXACT_NOTE",
    "FIELD_LABELS",
    "TEST_LABELS",
    "finds_caption",
    "id_caption",
    "parts_heading",
]

FIELD_LABELS: Final[dict[str, str]] = {
    "path_decoded": "Path (decoded)",
    "query_decoded": "Query string (decoded)",
    "target_decoded": "Path and query (decoded)",
    "user_agent_decoded": "User agent (decoded)",
    "referer_decoded": "Referer (decoded)",
    "method": "Method",
    "status": "Status code",
    "bytes_sent": "Bytes sent",
    "host": "Host",
    "extension": "File extension",
    "protocol": "Protocol",
    "path": "Path, as logged",
    "query": "Query string, as logged",
    "target": "Path and query, as logged",
    "user_agent": "User agent, as logged",
    "referer": "Referer, as logged",
}

TEST_LABELS: Final[dict[Test, str]] = {
    Test.CONTAINS: "contains",
    Test.REGEX: "matches pattern",
    Test.EQUALS: "is exactly",
    Test.ANY_OF: "is one of",
    Test.MIN: "is at least",
    Test.MAX: "is at most",
}

CATEGORY_LABELS: Final[dict[ActivityCategory, str]] = {
    ActivityCategory.INJECTION: "Injection",
    ActivityCategory.PATH_TRAVERSAL: "Path traversal",
    ActivityCategory.ACCESS_CONTROL: "Access control",
    ActivityCategory.CREDENTIAL_ATTACK: "Credential attack",
    ActivityCategory.SSRF: "SSRF",
    ActivityCategory.EXPLOITATION: "Exploitation",
    ActivityCategory.RECONNAISSANCE: "Reconnaissance",
    ActivityCategory.ENUMERATION: "Enumeration",
    ActivityCategory.CRAWLING: "Crawling",
    ActivityCategory.API_CALL: "API call",
    ActivityCategory.AUTHENTICATION: "Authentication",
    ActivityCategory.BROWSING: "Browsing",
    ActivityCategory.STATIC_ASSET: "Static asset",
}

#: Every text test ignores case, patterns included; said once under the rows
#: rather than promised away by a label such as "is exactly".
CASE_NOTE: Final = "Upper and lower case match alike."

DECODED_TIP: Final = (
    "Decoded fields are also cleaned up: nulls and comments removed, spaces collapsed."
)

EXACT_NOTE: Final = (
    '"is exactly" matches only this whole value, in any case. Use "matches pattern" to widen it.'
)


def id_caption(rule_id: str) -> str:
    return f"Saved with the id {rule_id}"


def finds_caption(find: Find | None, *, running: bool) -> str:
    """What the rule matches in the open case, so far or in all; None with no case."""
    if find is None:
        return "Open a case to see what it matches."
    said = f"{plural(find.lines, 'match', 'matches')} from {plural(find.clients, 'client')}"
    return f"{said} so far." if running else f"{said}."


def parts_heading(line_no: int) -> str:
    return f"Line {line_no}: tick what makes it suspicious."
