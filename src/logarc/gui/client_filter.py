"""Narrowing the client list to the address someone asked about.

Sorting the table answers *which client is worth opening*. It does not answer
*where is 203.0.113.66*, and that is the question an abuse report, a ticket or a
colleague arrives with — on a case with tens of thousands of clients, the only
previous answer was to scroll.

Free of Qt so the two judgements here can be tested without a display: what
counts as a match, and what the panel says about the result. The second is the
one that can misinform, and it does so in both directions. A filtered list
captioned "9 clients" describes a case containing nine clients, which is a lie
about the evidence. So is an unfiltered list of the busiest five hundred
captioned "119,880 clients": the reader cannot select 119,380 of them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from logarc.search import is_whole_address
from logarc.style import plural

if TYPE_CHECKING:
    from logarc.triage.scan import TriageProgress

__all__ = ["caption", "is_whole_address", "match_caption", "matches"]


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
    if is_whole_address(wanted):
        return client_ip == wanted
    return wanted in client_ip


def caption(
    *,
    shown: int,
    total: int,
    query: str,
    first: int = 1,
    matching: int | None = None,
    searching: bool = False,
    reordered: bool = False,
    missing_open: str | None = None,
) -> str:
    """What to write above the table for this result.

    Every filtered form names the total as well as the count shown. The panel is
    the only place a reader learns how large the case is, and a filter that
    silently rewrites that number would make a case of fifty thousand clients
    look like a case of nine.

    The list is one page of the case, or of the matches for `query`, starting at
    position `first` by request count. `matching` is how many clients in the
    whole case match `query`, when a search has answered; `searching` is the
    moment before it has. `reordered` says the page is sorted by something other
    than request count, so the order holds only within it. `missing_open` names
    the client being read when it is not among the rows shown.
    """
    text = _counts(
        shown=shown,
        total=total,
        query=query,
        first=first,
        matching=matching,
        searching=searching,
        reordered=reordered,
    )
    if missing_open:
        text += _outside(missing_open)
    return text


def match_caption(
    *,
    shown: int,
    total: int,
    query: str,
    first: int,
    matching: int,
    requests: int,
    counted: bool = True,
    reordered: bool = False,
    missing_open: str | None = None,
) -> str:
    """What to write above the clients a search of their requests found.

    Both numbers again: how many clients matched, of how many in the case, and
    how many requests that is. `counted` is false for a search the Where to
    start scan answered on its own, which knows which clients an activity
    reached but not in how many of their requests.
    """
    wanted = query.strip()
    if not counted and shown < matching:
        text = (
            f"Clients {first:,}\u2013{first + shown - 1:,} of {matching:,} that match {wanted}"
            " in the Where to start scan"
        )
    elif not counted:
        text = f"{matching:,} of {total:,} clients match {wanted} in the Where to start scan"
    elif matching == 0:
        text = f"No client sent a request matching {wanted}. {total:,} in the case."
    else:
        found = f" \u00b7 {plural(requests, 'request')}"
        if shown < matching:
            last = first + shown - 1
            order = ", sorted within this page" if reordered else ""
            text = (
                f"Clients {first:,}\u2013{last:,} of {matching:,} that sent a request"
                f" matching {wanted}{found}{order}"
            )
        else:
            text = f"{matching:,} of {total:,} clients sent a request matching {wanted}{found}"
    if missing_open:
        text += _outside(missing_open)
    return text


def _outside(client_ip: str) -> str:
    """Said after either caption when the client being read is not in the list."""
    return f" Current IP: {client_ip} (outside this list)."


def awaiting_scan(progress: TriageProgress | None, *, scanning: bool) -> str:
    """Why a search naming an activity has no answer yet.

    The list asks again by itself when the scan finishes, so this never tells the
    reader to; only a scan that is not running needs them to do anything.
    """
    opening = "Activities come from the Where to start scan, which"
    if not scanning:
        return f"{opening} has not finished. Run it from Where to start."
    so_far = (
        f": {progress.processed:,} of {progress.total:,} so far" if progress is not None else ""
    )
    return f"{opening} is still checking IPs{so_far}. The list fills in when it finishes."


def _counts(
    *,
    shown: int,
    total: int,
    query: str,
    first: int,
    matching: int | None,
    searching: bool,
    reordered: bool,
) -> str:
    wanted = query.strip()
    last = first + shown - 1
    if not wanted:
        if not total:
            return "No clients."
        if shown >= total:
            return plural(total, "client")
        # Paged. Named by the case's total alone, the caption would invite the
        # reader to select any client when only this page is there to select.
        order = " by request count, sorted within this page" if reordered else ", busiest first"
        return f"Clients {first:,}\u2013{last:,} of {total:,}{order}"
    if searching:
        return f"Searching the whole case for {wanted}\u2026"
    found = shown if matching is None else matching
    if found == 0:
        # Named as a filter result, not as an absence. An empty table with no
        # explanation reads as a broken tool or an empty case, and it is
        # neither.
        return f"No client matches {wanted}. {total:,} in the case."
    if shown < found:
        order = ", sorted within this page" if reordered else ""
        return f"Matches {first:,}\u2013{last:,} of {found:,} for {wanted}{order}"
    verb = "matches" if found == 1 else "match"
    return f"{found:,} of {total:,} clients {verb} {wanted}"
