"""Tests for the client filter's judgements, which need no display."""

from logarx.gui.client_filter import awaiting_scan, caption, match_caption, matches
from logarx.triage.scan import TriageProgress


def test_an_address_matches_itself() -> None:
    assert matches("203.0.113.66", "203.0.113.66")


def test_an_empty_filter_matches_everything() -> None:
    """Clearing the box has to put the whole case back, not empty the table."""
    assert matches("203.0.113.66", "")
    assert matches("203.0.113.66", "   ")


def test_a_partial_address_matches() -> None:
    assert matches("203.0.113.66", "113.66")
    assert matches("203.0.113.66", "203")


def test_a_trailing_dot_keeps_a_neighbouring_block_out() -> None:
    """`203.0.3.` means that /24 and nothing else. Without this, a filter typed
    to isolate one block quietly answers with another one's traffic, and a
    subnet is exactly the thing an abuse report names."""
    assert matches("203.0.3.9", "203.0.3.")
    assert not matches("203.0.30.5", "203.0.3.")
    assert not matches("203.0.31.7", "203.0.3.")


def test_a_whole_address_matches_only_itself() -> None:
    """Typing a complete address is a request for that client, not for the ten
    others whose last octet begins with the same digits.

    Found by looking at the panel rather than at a test: `203.0.3.9` listed
    eleven rows, because `203.0.3.90` through `.99` all contain it. An
    investigator copying an address out of a ticket could then open
    `203.0.3.90` and write up the wrong client — the exact mistake this tool
    exists to prevent.
    """
    assert matches("203.0.3.9", "203.0.3.9")
    assert not matches("203.0.3.90", "203.0.3.9")
    assert not matches("203.0.3.99", "203.0.3.9")


def test_a_partial_address_still_searches_loosely() -> None:
    """Only a complete address is treated as exact. Anything shorter is still a
    search, which is what makes a subnet or a remembered tail work at all."""
    assert matches("203.0.3.90", "203.0.3.")
    assert matches("203.0.3.90", "0.3.9")
    assert matches("203.0.3.90", "203.0")


def test_something_that_is_not_an_address_is_not_treated_as_one() -> None:
    """Four dotted parts are not enough to be an address; they have to be
    numbers in range, or a search for text containing dots would silently stop
    matching anything."""
    assert matches("203.0.3.9", "3.9")
    assert not matches("203.0.3.9", "1.2.3.4")
    # 999 is not an octet, so this stays a substring search and finds nothing.
    assert not matches("203.0.3.9", "203.0.3.999")


def test_surrounding_space_is_ignored() -> None:
    """Addresses get pasted out of tickets and mail, and they arrive with
    whitespace attached."""
    assert matches("203.0.113.66", "  203.0.113.66  ")
    assert matches("203.0.113.66", "\t113.66\n")


def test_an_address_that_does_not_contain_the_filter_is_out() -> None:
    assert not matches("203.0.113.66", "198.51")


def test_the_caption_says_how_many_of_the_whole_case_match() -> None:
    """A filtered list reading "9 clients" describes a case with nine clients
    in it. The total has to stay on screen or the filter misreports the case."""
    assert caption(shown=9, total=49_175, query="203.0.3.") == (
        "9 of 49,175 clients match 203.0.3."
    )


def test_unfiltered_caption_keeps_the_case_count_without_extra_instructions() -> None:
    assert caption(shown=49_175, total=49_175, query="") == "49,175 clients"


def test_a_capped_list_says_it_holds_only_the_busiest_of_them() -> None:
    """The table holds the busiest few hundred, so a case of a hundred thousand
    clients is not a hundred thousand rows.

    Captioned with the case's total alone it invites the reader to select any of
    them, and 119,380 of them are not there to select. Captioned with the row
    count instead — which is what it did — it reports a case of 119,880 clients
    as a case of 500.
    """
    assert caption(shown=500, total=119_880, query="") == (
        "Clients 1\u2013500 of 119,880, busiest first"
    )


def test_one_match_is_not_called_clients() -> None:
    assert caption(shown=1, total=49_175, query="203.0.113.66") == (
        "1 of 49,175 clients matches 203.0.113.66"
    )


def test_no_match_says_so_rather_than_leaving_an_empty_table() -> None:
    """An empty table with no explanation reads as a broken tool or an empty
    case. It is neither: it is a filter that matched nothing."""
    assert caption(shown=0, total=49_175, query="10.0.0.1") == (
        "No client matches 10.0.0.1. 49,175 in the case."
    )


def test_an_empty_case_is_not_described_as_a_filter_result() -> None:
    """Before a case is open there is nothing to filter, and saying "no client
    matches" would blame a filter the user has not typed."""
    assert caption(shown=0, total=0, query="") == "No clients."


def test_a_later_page_says_which_clients_it_holds() -> None:
    assert caption(shown=431, total=931, query="", first=501) == (
        "Clients 501\u2013931 of 931, busiest first"
    )


def test_a_page_sorted_another_way_says_the_order_is_only_within_it() -> None:
    assert caption(shown=500, total=931, query="", reordered=True) == (
        "Clients 1\u2013500 of 931 by request count, sorted within this page"
    )


def test_while_the_whole_case_is_searched_the_caption_says_so() -> None:
    assert caption(shown=3, total=931, query="10.0", searching=True) == (
        "Searching all clients for 10.0\u2026"
    )


def test_a_whole_case_result_names_the_count_of_matches() -> None:
    assert caption(shown=1, total=2_760, query="100.99.203.115", matching=1) == (
        "1 of 2,760 clients matches 100.99.203.115"
    )
    assert caption(shown=0, total=2_760, query="10.9.9.9", matching=0) == (
        "No client matches 10.9.9.9. 2,760 in the case."
    )


def test_more_matches_than_a_page_are_paged() -> None:
    assert caption(shown=500, total=2_760, query="10.0", matching=1_234, first=501) == (
        "Matches 501\u20131,000 of 1,234 for 10.0"
    )


def test_an_open_client_outside_the_list_is_named() -> None:
    text = caption(shown=500, total=931, query="", missing_open="100.99.203.115")
    # A line of its own: run on after the counts it read as part of them.
    assert text.endswith("\nCurrent client: 100.99.203.115 (not in this list).")


def test_an_activity_search_waits_for_the_scan_and_says_how_far_it_has_got() -> None:
    """Asked again by itself when the scan finishes, so it never says "ask again"."""
    assert awaiting_scan(TriageProgress(40, 1_200, ()), scanning=True) == (
        "Activities come from the Triage scan, which is still checking clients:"
        " 40 of 1,200 so far. The list fills in when it finishes."
    )
    assert awaiting_scan(None, scanning=True) == (
        "Activities come from the Triage scan, which is still checking clients."
        " The list fills in when it finishes."
    )


def test_an_activity_search_with_no_scan_running_says_where_to_start_one() -> None:
    assert awaiting_scan(None, scanning=False) == (
        "Activities come from the Triage scan, which has not finished. Run it from Triage."
    )


def test_an_open_client_outside_a_search_is_named_as_outside_any_list() -> None:
    """In the words the list uses without a search, so the two read alike."""
    from logarx.gui.client_filter import match_caption

    text = match_caption(
        shown=2, total=52, query="status:404", first=1, matching=2, requests=9,
        missing_open="100.99.203.115",
    )  # fmt: skip

    # A line of its own: run on after the counts it read as part of them.
    assert text.endswith("\nCurrent client: 100.99.203.115 (not in this list).")


def test_an_activity_on_more_clients_than_a_page_names_the_page() -> None:
    """On the large tier `activity:api_call` names 4,916 clients and a page holds
    500; the caption read as though every one of them were listed."""
    from logarx.gui.client_filter import match_caption

    paged = match_caption(
        shown=500, total=7_450, query="activity:api_call", first=501, matching=4_916,
        requests=0, counted=False,
    )  # fmt: skip
    whole = match_caption(
        shown=3, total=7_450, query="activity:injection", first=1, matching=3,
        requests=0, counted=False,
    )  # fmt: skip

    assert paged == (
        "Clients 501\u20131,000 of 4,916 that match activity:api_call in the Triage scan"
    )
    assert whole == "3 of 7,450 clients match activity:injection in the Triage scan"


def test_a_page_of_a_search_names_answered_says_so() -> None:
    text = match_caption(
        shown=100, total=900, query="office", first=1, matching=501, requests=0, named=True
    )

    assert "or have a name holding it" in text


def test_only_an_activity_search_is_credited_to_the_triage_scan() -> None:
    named = match_caption(
        shown=0, total=900, query="name:nobody", first=1, matching=0, requests=0, counted=False
    )
    scanned = match_caption(
        shown=2,
        total=900,
        query="activity:injection",
        first=1,
        matching=2,
        requests=0,
        counted=False,
    )

    assert "Triage" not in named
    assert scanned.endswith("in the Triage scan")
