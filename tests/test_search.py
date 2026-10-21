"""The filter language both search boxes speak.

What a token means, which tokens become chips, and whether one request matches.
The case-wide search answers the same question in SQL; the parity between the two
is held in `tests/storage/test_search_clients.py`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.search import (
    ANY_DAY,
    Scope,
    Suggestion,
    decoded_path,
    decoded_target,
    evidence_part,
    fold,
    is_whole_address,
    labels_for_activity,
    parse,
    suggestions,
    tokens,
    understood,
    value_counts,
    without_time,
)

NOON = datetime(2026, 3, 11, 12, 0, tzinfo=UTC)


def event(
    path: str | None = "/",
    status: int | None = 200,
    *,
    query: str | None = None,
    method: str | None = "GET",
    at: datetime = NOON,
    ip: str = "198.51.100.31",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=at,
        client_ip=ip,
        evidence=EvidenceRef("access.log", 1),
        method=method,
        path=path,
        query=query,
        status=status,
    )


# -- what the box understands -------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "status:404",
        "status:4xx",
        "STATUS:5XX",
        "path:/admin",
        'path:"/my files"',
        "method:post",
        "after:2026-03-11",
        "before:2026-03-11T14:05",
        "after:14:05",
        "before:14:05:30",
    ],
)
def test_a_known_filter_with_a_good_value_is_understood(token: str) -> None:
    assert understood(token, Scope.EVIDENCE)


@pytest.mark.parametrize(
    "token",
    [
        "stat:404",
        "status:abc",
        "status:4040",
        "status:6xx",
        "status:",
        "path:",
        "method:G3T",
        "after:yesterday",
        "after:2026-13-01",
        "after:25:00",
        "union",
        '"union select"',
        "ip:10.0.0.1",
        "activity:injection",
    ],
)
def test_anything_else_is_not_a_chip_in_the_evidence_box(token: str) -> None:
    """A typo must never become a silent filter, and one client's lines have no
    other address and no activity names to filter by."""
    assert not understood(token, Scope.EVIDENCE)


def test_the_case_box_also_understands_addresses_and_activities() -> None:
    assert understood("ip:198.51", Scope.CASE)
    assert understood("activity:injection", Scope.CASE)
    assert not understood("ip:not-an-address", Scope.CASE)
    assert not understood("198.51.100.31", Scope.CASE), "a bare address stays as typed"


def test_quotes_group_a_phrase_and_an_unclosed_quote_runs_to_the_end() -> None:
    assert tokens('status:404  path:"/my files" "union select" x') == [
        "status:404",
        'path:"/my files"',
        '"union select"',
        "x",
    ]
    assert tokens('a "b c') == ["a", '"b c']
    assert tokens("   ") == []


# -- what a query matches -------------------------------------------------------------


def test_a_status_matches_exactly_and_a_class_matches_its_hundred() -> None:
    assert parse("status:404", Scope.EVIDENCE).matches(event(status=404))
    assert not parse("status:404", Scope.EVIDENCE).matches(event(status=403))
    assert parse("status:4xx", Scope.EVIDENCE).matches(event(status=499))
    assert not parse("status:4xx", Scope.EVIDENCE).matches(event(status=500))
    assert not parse("status:4xx", Scope.EVIDENCE).matches(event(status=None))


def test_the_same_key_twice_is_either_and_different_keys_are_both() -> None:
    query = parse("status:403 status:404 path:/admin", Scope.EVIDENCE)
    assert query.matches(event("/admin/x", 403))
    assert query.matches(event("/admin/y", 404))
    assert not query.matches(event("/admin/z", 200))
    assert not query.matches(event("/shop", 404))


def test_a_path_matches_raw_or_decoded_and_ignores_case() -> None:
    assert parse("path:/ADMIN", Scope.EVIDENCE).matches(event("/admin/users"))
    assert parse('path:"/my files"', Scope.EVIDENCE).matches(event("/my%20files/a"))
    assert parse("path:%20", Scope.EVIDENCE).matches(event("/my%20files/a"))
    assert not parse("path:/admin", Scope.EVIDENCE).matches(event("/shop", query="next=/admin"))


def test_a_method_ignores_case() -> None:
    assert parse("method:post", Scope.EVIDENCE).matches(event(method="POST"))
    assert not parse("method:post", Scope.EVIDENCE).matches(event(method="GET"))
    assert not parse("method:post", Scope.EVIDENCE).matches(event(method=None))


def test_words_search_the_request_as_the_panel_shows_it() -> None:
    """`+` is a space in the query and a plus in the path, as `decode_target` reads them."""
    query = parse("union select", Scope.EVIDENCE)
    assert query.matches(event("/s", query="q=1+UNION%20SELECT+2"))
    assert not query.matches(event("/s", query="q=union"))
    assert parse("a+b", Scope.EVIDENCE).matches(event("/a+b"))
    assert parse('"union select"', Scope.EVIDENCE).matches(event("/s", query="q=UNION+SELECT"))


def test_a_typo_is_searched_as_text_and_finds_nothing() -> None:
    assert parse("stat:404", Scope.EVIDENCE).words == ("stat:404",)
    assert not parse("stat:404", Scope.EVIDENCE).matches(event(status=404))


def test_a_pending_key_is_neither_a_filter_nor_a_word() -> None:
    """`status:` while the value list is open must not flash "No results found"."""
    query = parse("status:", Scope.EVIDENCE)
    assert query.is_empty
    assert query.matches(event())


def test_after_is_inclusive_and_before_is_not() -> None:
    query = parse("after:2026-03-11T12:00 before:2026-03-11T12:05", Scope.EVIDENCE)
    assert query.matches(event(at=NOON))
    assert query.matches(event(at=NOON + timedelta(minutes=4, seconds=59)))
    assert not query.matches(event(at=NOON + timedelta(minutes=5)))
    assert not query.matches(event(at=NOON - timedelta(seconds=1)))


def test_a_date_alone_is_midnight_utc() -> None:
    query = parse("before:2026-03-12", Scope.EVIDENCE)
    assert query.before == datetime(2026, 3, 12, tzinfo=UTC)


def test_a_time_of_day_is_read_on_the_day_the_box_gives() -> None:
    query = parse("after:14:05", Scope.EVIDENCE, day=date(2026, 3, 11))
    assert query.after == datetime(2026, 3, 11, 14, 5, tzinfo=UTC)
    assert parse("after:14:05", Scope.EVIDENCE).after is None, "no day, no guess"


def test_an_empty_query_matches_everything() -> None:
    assert parse("", Scope.EVIDENCE).is_empty
    assert parse("", Scope.EVIDENCE).matches(event())


# -- the case box -------------------------------------------------------------------


def test_a_bare_address_in_the_case_box_is_an_address_search() -> None:
    query = parse("198.51", Scope.CASE)
    assert query.ips == ("198.51",)
    assert query.words == ()
    assert query.is_address_only


def test_a_bare_word_in_the_case_box_searches_requests() -> None:
    query = parse("wp-login", Scope.CASE)
    assert query.words == ("wp-login",)
    assert not query.is_address_only
    assert query.has_request_filters


def test_a_whole_address_matches_only_itself() -> None:
    assert parse("ip:203.0.3.9", Scope.CASE).matches(event(ip="203.0.3.9"))
    assert not parse("ip:203.0.3.9", Scope.CASE).matches(event(ip="203.0.3.90"))
    assert parse("ip:203.0.3", Scope.CASE).matches(event(ip="203.0.3.90"))
    assert is_whole_address("203.0.3.9")
    assert not is_whole_address("203.0.3")


def test_activities_are_kept_for_the_client_level_and_ignored_per_request() -> None:
    query = parse("activity:injection status:200", Scope.CASE)
    assert query.activities == ("injection",)
    assert query.matches(event(status=200))


# -- decoding -----------------------------------------------------------------------


def test_invalid_utf8_falls_back_to_the_raw_bytes() -> None:
    """DuckDB's `url_decode` refuses these; the SQL keeps the raw value, so this does too."""
    assert decoded_path("/a%C3%28") == "/a%C3%28"
    assert decoded_target("/a%C3%28", "q=%41") == "/a%C3%28?q=A"


def test_decoding_is_one_pass_and_leaves_broken_escapes_alone() -> None:
    assert decoded_path("/%2541") == "/%41"
    assert decoded_path("/bad%zz") == "/bad%zz"
    assert decoded_path("/x%") == "/x%"


def test_a_target_without_a_path_is_empty_as_the_event_has_it() -> None:
    assert decoded_target("", "q=1") == ""
    assert decoded_target("/p", "") == "/p"


# -- the store must agree with every one of these ---------------------------------------
#
# The case box asks DuckDB and the evidence box asks Python, and the two must
# keep the same lines. Over all of Unicode their lower-casing differs in exactly
# two places (measured: Python 3.12, DuckDB 1.5.5), and their upper-casing in a
# hundred, so the language settles each one rather than leaving it to whichever
# side happens to run.


def test_a_dotted_capital_i_is_found_by_a_plain_i() -> None:
    """Python lower-cases it to `i` and a combining dot, which a reader typing
    `iletisim` with an ordinary i would never match; DuckDB to `i`."""
    assert parse("\u0130let", Scope.EVIDENCE).matches(event("/\u0130letisim"))
    assert parse("ilet", Scope.EVIDENCE).matches(event("/\u0130letisim"))
    assert parse("path:/ilet", Scope.EVIDENCE).matches(event("/\u0130letisim"))


def test_a_final_sigma_is_any_sigma() -> None:
    """Python writes a capital sigma at a word's end as the final form, DuckDB as
    the ordinary one; both are read as one letter."""
    word = "\u03bf\u03b4\u03bf\u03c3"
    assert parse(word, Scope.EVIDENCE).matches(event("/\u039f\u0394\u039f\u03a3"))
    assert parse(word, Scope.EVIDENCE).matches(event("/\u03bf\u03b4\u03bf\u03c2"))
    assert fold("\u039f\u0394\u039f\u03a3") == fold("\u03bf\u03b4\u03bf\u03c3")


def test_a_method_outside_ascii_never_matches() -> None:
    """A method can only be typed in letters a to z. Upper-cased by Python, a
    dotless i turns `P\u0131NG` into `PING`; DuckDB leaves it alone. Neither is
    a method anybody asked for."""
    assert not parse("method:PING", Scope.EVIDENCE).matches(event(method="P\u0131NG"))
    assert parse("method:ping", Scope.EVIDENCE).matches(event(method="PING"))


# -- activity: names what the scan saw ------------------------------------------------

LABELS = (
    ("directory_enumeration", "Directory Enumeration", "enumeration"),
    ("content_discovery_user_agent", "Content Discovery Tool", "enumeration"),
    ("crs:942100", "SQL Injection Attack Detected via libinjection", "injection"),
    ("benign:browsing", "Browsing", "browsing"),
    ("dot_dot_segment", "Dot-dot Segment", "path_traversal"),
)


def test_an_activity_is_a_category() -> None:
    assert labels_for_activity(LABELS, "enumeration") == {
        "directory_enumeration",
        "content_discovery_user_agent",
    }
    assert labels_for_activity(LABELS, "INJECTION") == {"crs:942100"}


def test_a_category_can_be_typed_with_a_space() -> None:
    assert labels_for_activity(LABELS, "path traversal") == {"dot_dot_segment"}


def test_an_activity_is_also_part_of_a_rule_name() -> None:
    assert labels_for_activity(LABELS, "discovery") == {"content_discovery_user_agent"}
    assert labels_for_activity(LABELS, "libinjection") == {"crs:942100"}


def test_an_activity_nothing_was_called_finds_nothing() -> None:
    assert labels_for_activity(LABELS, "ransomware") == frozenset()
    assert labels_for_activity(LABELS, "") == frozenset()


# -- a case search, taken apart -------------------------------------------------------


def test_what_a_case_search_hands_the_evidence_box() -> None:
    """Opened from a case search, a client's evidence is filtered by the same
    request filters; who sent them and when are the case's to answer."""
    text = (
        "status:200 10.0.0.1 ip:10.9 activity:injection path:/admin "
        '"union select" after:2026-03-09 method: method:GET'
    )

    assert evidence_part(text) == 'status:200 path:/admin "union select" method:GET'


def test_a_case_search_of_only_clients_hands_the_evidence_box_nothing() -> None:
    assert evidence_part("10.0.0.1 ip:10.9 activity:injection") == ""
    assert evidence_part("") == ""


def test_a_time_in_the_case_box_is_taken_out_to_move_the_range() -> None:
    assert without_time("after:2026-03-09 status:404 before:14:30 10.0") == "status:404 10.0"
    assert without_time("status:404") == "status:404"
    assert without_time("after:soon status:404") == "after:soon status:404", "a word, not a time"


def test_any_day_makes_a_time_of_day_a_filter() -> None:
    """Asked without a day, a time of day is no filter; with any day at all, it is."""
    assert parse("after:14:05", Scope.CASE).is_empty
    assert not parse("after:14:05", Scope.CASE, day=ANY_DAY).is_empty


# -- what the suggestion list offers --------------------------------------------------


def test_values_are_counted_most_common_first_then_the_classes() -> None:
    events = [event(status=404)] * 3 + [event(status=200), event(status=500), event(status=None)]

    assert value_counts(events, "status") == [
        ("404", 3),
        ("200", 1),
        ("500", 1),
        ("2xx", 1),
        ("4xx", 3),
        ("5xx", 1),
    ]


def test_methods_are_counted_as_written_upper_case() -> None:
    events = [event(method="get"), event(method="GET"), event(method="POST"), event(method=None)]

    assert value_counts(events, "method") == [("GET", 2), ("POST", 1)]


def test_a_status_the_box_cannot_take_is_not_offered() -> None:
    events = [event(status=999), event(status=0), event(status=301)]

    assert value_counts(events, "status") == [("301", 1), ("3xx", 1)]


def test_a_method_the_box_cannot_take_is_not_offered() -> None:
    """`method:M-SEARCH` is not a filter the box understands, so offering it
    would complete to text that finds nothing."""
    events = [event(method="M-SEARCH"), event(method="P\u0131NG"), event(method="GET")]

    assert value_counts(events, "method") == [("GET", 1)]


def completions(rows: tuple[Suggestion, ...]) -> list[str]:
    return [row.completion for row in rows]


def test_an_empty_box_offers_every_filter_and_says_text_works_too() -> None:
    title, rows = suggestions("", Scope.EVIDENCE, {})

    assert title == "FILTER BY"
    assert completions(rows) == ["status:", "path:", "method:", "after:", "before:", "any text"]
    assert [row.selectable for row in rows] == [True] * 5 + [False]


def test_the_case_box_offers_addresses_and_activities_as_well() -> None:
    _, rows = suggestions("", Scope.CASE, {})

    assert "ip:" in completions(rows)
    assert "activity:" in completions(rows)


def test_a_partial_key_narrows_the_filters() -> None:
    assert completions(suggestions("st", Scope.EVIDENCE, {})[1]) == ["status:"]
    assert completions(suggestions("IP", Scope.CASE, {})[1]) == ["ip:"]
    assert suggestions("ip", Scope.EVIDENCE, {}) == ("", ())
    assert suggestions("xyz", Scope.EVIDENCE, {}) == ("", ())


def test_after_a_key_it_offers_the_values_there_are() -> None:
    values = {"status": [("404", "3,555 lines"), ("200", "9 lines")]}

    title, rows = suggestions(
        "status:", Scope.EVIDENCE, values, values_title="VALUES IN THIS ACTIVITY"
    )

    assert title == "VALUES IN THIS ACTIVITY"
    assert completions(rows) == ["status:404", "status:200"]
    assert rows[0].note == "3,555 lines"
    assert completions(suggestions("Status:2", Scope.EVIDENCE, values)[1]) == ["status:200"]


def test_a_key_with_no_values_to_offer_offers_nothing() -> None:
    assert suggestions("path:", Scope.EVIDENCE, {"status": [("404", "1 line")]}) == ("", ())


def test_the_case_box_is_titled_for_what_it_searches() -> None:
    title, _rows = suggestions("", Scope.CASE, {})

    assert title == "SEARCH CLIENTS BY"


def test_the_activity_filter_names_the_tab_it_comes_from() -> None:
    _title, rows = suggestions("", Scope.CASE, {})
    (activity,) = [row for row in rows if row.completion == "activity:"]

    assert activity.note.endswith("(per client, from Triage)")
