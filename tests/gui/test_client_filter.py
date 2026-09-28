"""Tests for the client filter's judgements, which need no display."""

from logarc.gui.client_filter import caption, matches


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


def test_the_caption_without_a_filter_is_the_one_it_always_was() -> None:
    assert caption(shown=49_175, total=49_175, query="") == (
        "49,175 clients. Select one to reconstruct what it did."
    )


def test_a_capped_list_says_it_holds_only_the_busiest_of_them() -> None:
    """The table holds the busiest few hundred, so a case of a hundred thousand
    clients is not a hundred thousand rows.

    Captioned with the case's total alone it invites the reader to select any of
    them, and 119,380 of them are not there to select. Captioned with the row
    count instead — which is what it did — it reports a case of 119,880 clients
    as a case of 500.
    """
    assert caption(shown=500, total=119_880, query="") == (
        "Clients 1\u2013500 of 119,880, busiest first. Select one to reconstruct what it did."
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
        "Clients 501\u2013931 of 931, busiest first. Select one to reconstruct what it did."
    )


def test_a_page_sorted_another_way_says_the_order_is_only_within_it() -> None:
    assert caption(shown=500, total=931, query="", reordered=True) == (
        "Clients 1\u2013500 of 931 by request count, sorted within this page. "
        "Select one to reconstruct what it did."
    )


def test_while_the_whole_case_is_searched_the_caption_says_so() -> None:
    assert caption(shown=3, total=931, query="10.0", searching=True) == (
        "Searching the whole case for 10.0\u2026"
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
    assert text.endswith(
        " 100.99.203.115, open now, is not in this list; filter by its address to show it."
    )
