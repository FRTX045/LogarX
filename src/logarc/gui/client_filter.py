"""Narrowing the client list to the address someone asked about.

Sorting the table answers *which client is worth opening*. It does not answer
*where is 203.0.113.66*, and that is the question an abuse report, a ticket or a
colleague arrives with — on a case with tens of thousands of clients, the only
previous answer was to scroll.

Free of Qt so the two judgements here can be tested without a display: what
counts as a match, and what the panel says about the result. The second is the
one that can misinform. A filtered list captioned "9 clients" describes a case
containing nine clients, which is a lie about the evidence; the total has to
stay on screen beside it.
"""

from __future__ import annotations

from logarc.gui.style import plural

__all__ = ["caption", "matches"]


def _is_whole_address(text: str) -> bool:
    """Whether `text` is a complete IPv4 address rather than part of one."""
    parts = text.split(".")
    return len(parts) == 4 and all(
        part.isdigit() and len(part) <= 3 and int(part) <= 255 for part in parts
    )


def matches(client_ip: str, query: str) -> bool:
    """Whether `client_ip` should stay on screen while `query` is typed.

    A **complete address is matched exactly**. Typing one is a request for that
    client, and substring matching answered it with ten more: `203.0.3.9` also
    appears inside `203.0.3.90` through `.99`. An investigator copying an
    address out of a ticket could open the wrong one of those eleven rows and
    write up a client that did nothing — the precise mistake this tool exists
    to prevent. Found by looking at the panel, not by reading the code.

    **Anything shorter is a substring search**, which is what makes the partial
    forms work — a remembered tail (`113.66`) finds an address as readily as
    its leading octets do.

    The dot does the precise work there. A filter of `203.0.3.` cannot match
    `203.0.30.5`, because after `203.0.3` that address continues with a digit
    rather than the separator — so typing the trailing dot isolates exactly one
    /24, while leaving it off keeps the looser search.
    """
    wanted = query.strip()
    if not wanted:
        return True
    if _is_whole_address(wanted):
        return client_ip == wanted
    return wanted in client_ip


def caption(*, shown: int, total: int, query: str) -> str:
    """What to write above the table for this result.

    Every filtered form names the total as well as the count shown. The panel is
    the only place a reader learns how large the case is, and a filter that
    silently rewrites that number would make a case of fifty thousand clients
    look like a case of nine.
    """
    if not query.strip():
        # The unfiltered wording is unchanged: this is the sentence the panel
        # has always opened with, and it tells a new reader what to do next.
        return (
            f"{plural(total, 'client')}. Select one to reconstruct what it did."
            if total
            else "No clients."
        )

    wanted = query.strip()
    if shown == 0:
        # Named as a filter result, not as an absence. An empty table with no
        # explanation reads as a broken tool or an empty case, and it is
        # neither.
        return f"No client matches {wanted}. {total:,} in the case."
    verb = "matches" if shown == 1 else "match"
    return f"{shown:,} of {total:,} clients {verb} {wanted}"
