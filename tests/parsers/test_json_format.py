"""Reading a log that writes one JSON object per line.

The second kind of format, and the one that decides whether the storage shape
from stage 1 was general enough. It works the other way round from a LogFormat
directive — matching names rather than positions — so nothing about it can lean
on the first kind having been an Apache directive.
"""

from __future__ import annotations

import json

import pytest

from zodiarc.core.evidence import EvidenceRef
from zodiarc.parsers.json_format import JsonFormatError, guess_mapping
from zodiarc.parsers.spec import JsonFormatSpec, spec_from_dict, spec_to_dict

REF = EvidenceRef(source_file_id="f", line_no=1)

#: A gateway line of the shape nginx writes with its JSON escaping, which is
#: the most common one in the wild.
GATEWAY = {
    "time": "2024-05-01T09:00:45+00:00",
    "remote_addr": "203.0.113.77",
    "request": "GET /admin/0.php?id=1 HTTP/1.1",
    "status": 404,
    "body_bytes_sent": 0,
    "http_referer": "-",
    "http_user_agent": "curl/8.4.0",
    "host": "shop.example.com",
}

MAPPED = JsonFormatSpec(
    name="gateway",
    fields=(
        ("timestamp", "time"),
        ("client_ip", "remote_addr"),
        ("request_line", "request"),
        ("status", "status"),
        ("bytes_sent", "body_bytes_sent"),
        ("referer", "http_referer"),
        ("user_agent", "http_user_agent"),
        ("host", "host"),
    ),
)


def line(**changes: object) -> str:
    return json.dumps({**GATEWAY, **changes})


# -- reading ---------------------------------------------------------------


def test_a_mapped_line_becomes_an_event() -> None:
    event = MAPPED.build().parse_line(line(), REF)

    assert event is not None
    assert event.client_ip == "203.0.113.77"
    assert event.status == 404
    assert event.host == "shop.example.com"
    assert event.user_agent == "curl/8.4.0"


def test_a_request_line_is_split_the_same_way_a_directive_splits_one() -> None:
    """`%r` and a `request` key hold the same thing, so they have to come apart
    into the same three fields — otherwise the same traffic reconstructs
    differently depending on which format read it."""
    event = MAPPED.build().parse_line(line(), REF)

    assert event is not None
    assert event.method == "GET"
    assert event.path == "/admin/0.php"
    assert event.query == "id=1"
    assert event.protocol == "HTTP/1.1"


def test_the_three_parts_can_be_mapped_separately_instead() -> None:
    """Plenty of logs write method, path and status as their own keys and never
    assemble a request line at all."""
    spec = JsonFormatSpec(
        name="split",
        fields=(
            ("timestamp", "ts"),
            ("client_ip", "ip"),
            ("method", "verb"),
            ("path", "uri"),
            ("status", "code"),
        ),
    )

    event = spec.build().parse_line(
        json.dumps(
            {
                "ts": "2024-05-01T09:00:45Z",
                "ip": "203.0.113.5",
                "verb": "POST",
                "uri": "/login",
                "code": 302,
            }
        ),
        REF,
    )

    assert event is not None
    assert event.method == "POST"
    assert event.path == "/login"
    assert event.status == 302


def test_a_dash_is_absent_the_same_way_it_is_in_a_text_log() -> None:
    event = MAPPED.build().parse_line(line(), REF)

    assert event is not None
    assert event.referer is None


def test_a_key_the_line_does_not_carry_is_absent_rather_than_fatal() -> None:
    without_host = {key: value for key, value in GATEWAY.items() if key != "host"}

    event = MAPPED.build().parse_line(json.dumps(without_host), REF)

    assert event is not None
    assert event.host is None


def test_a_nested_key_can_be_reached_by_its_path() -> None:
    """Gateways routinely nest. Without this the reader has to pre-process
    their own evidence before Zodiarc will look at it."""
    spec = JsonFormatSpec(
        name="nested",
        fields=(("timestamp", "ts"), ("client_ip", "client.ip"), ("status", "response.status")),
    )

    event = spec.build().parse_line(
        json.dumps(
            {
                "ts": "2024-05-01T09:00:45Z",
                "client": {"ip": "203.0.113.5"},
                "response": {"status": 500},
            }
        ),
        REF,
    )

    assert event is not None
    assert event.client_ip == "203.0.113.5"
    assert event.status == 500


def test_keys_that_were_not_mapped_are_kept_rather_than_dropped() -> None:
    """The same promise the directive compiler makes: a field with no place in
    the canonical schema is still evidence, and is kept beside the event."""
    event = MAPPED.build().parse_line(line(request_id="req-000042"), REF)

    assert event is not None
    assert event.extra["request_id"] == "req-000042"


# -- what is not a line of this log ----------------------------------------


def test_a_mapped_key_is_not_also_kept_among_the_extras() -> None:
    """It would be stored twice — once as the field it is and once beside it —
    and the evidence table would show the same value in two columns, one of
    them named after somebody else's schema."""
    event = MAPPED.build().parse_line(line(request_id="req-000042"), REF)

    assert event is not None
    assert set(event.extra) == {"request_id"}


def test_a_line_that_is_not_json_is_refused() -> None:
    assert MAPPED.build().parse_line("203.0.113.5 - - [10/Oct/2000] ...", REF) is None


def test_a_json_array_is_refused() -> None:
    """Valid JSON, and not a log line. Accepting it would let a format score
    well against a file of anything at all."""
    assert MAPPED.build().parse_line("[1, 2, 3]", REF) is None


def test_a_line_nested_past_the_recursion_limit_is_refused_not_fatal() -> None:
    """`json.loads` raises `RecursionError`, which is not a `ValueError`.

    Found by auditing the tool as a target rather than as an examiner. A line
    of twenty thousand `[` characters ended a whole ingest: format detection
    scores every registered parser against the sample, this one recursed past
    Python's limit, and the error travelled out through `score_parser`,
    `detect_format` and `ingest_file` untouched.

    Detection happens before the log's real format is chosen, so a single
    crafted line stopped a case being made at all, whatever kind of log it
    was — and the quarantine record, which exists so that a line too damaged
    to read is counted rather than fatal, never saw it.
    """
    assert MAPPED.build().parse_line("[" * 20_000 + "]" * 20_000, REF) is None


def test_a_line_with_no_time_is_refused() -> None:
    """No timestamp, no event — the same rule the directive compiler applies,
    and for the same reason: everything downstream is ordered by time."""
    without_time = {key: value for key, value in GATEWAY.items() if key != "time"}

    assert MAPPED.build().parse_line(json.dumps(without_time), REF) is None


def test_a_line_with_no_client_is_refused() -> None:
    without_client = {key: value for key, value in GATEWAY.items() if key != "remote_addr"}

    assert MAPPED.build().parse_line(json.dumps(without_client), REF) is None


# -- times -----------------------------------------------------------------


@pytest.mark.parametrize(
    "written",
    [
        "2024-05-01T09:00:45+00:00",
        "2024-05-01T09:00:45Z",
        "2024-05-01T09:00:45.123Z",
        "2024-05-01 09:00:45+0000",
    ],
)
def test_the_usual_iso_spellings_are_read_without_being_told(written: str) -> None:
    event = MAPPED.build().parse_line(line(time=written), REF)

    assert event is not None
    assert event.timestamp.year == 2024
    assert event.timestamp.hour == 9


def test_epoch_seconds_are_read_without_being_told() -> None:
    """Docker and a good many gateways write a number."""
    event = MAPPED.build().parse_line(line(time=1714554045), REF)

    assert event is not None
    assert event.timestamp.hour == 9


def test_epoch_milliseconds_are_told_apart_from_seconds() -> None:
    """Read as seconds, a millisecond stamp lands in the year 56000 — and
    nothing downstream would question it, it would just sort last for ever."""
    event = MAPPED.build().parse_line(line(time=1714554045123), REF)

    assert event is not None
    assert event.timestamp.year == 2024


def test_a_time_format_of_the_site_s_own_is_used_when_given() -> None:
    spec = JsonFormatSpec(
        name="odd-time",
        fields=(("timestamp", "time"), ("client_ip", "remote_addr")),
        time_format="%d/%b/%Y %H:%M:%S %z",
    )

    event = spec.build().parse_line(
        json.dumps({"time": "01/May/2024 09:00:45 +0000", "remote_addr": "203.0.113.5"}), REF
    )

    assert event is not None
    assert event.timestamp.hour == 9


def test_a_time_that_does_not_fit_refuses_the_line_rather_than_guessing() -> None:
    assert MAPPED.build().parse_line(line(time="last Tuesday"), REF) is None


# -- building one ----------------------------------------------------------


def test_a_format_with_no_time_mapped_is_refused_when_it_is_built() -> None:
    """Caught here rather than at ingest, where it would quarantine every line
    of the log and present as an empty case."""
    with pytest.raises(JsonFormatError, match="timestamp"):
        JsonFormatSpec(name="no-time", fields=(("client_ip", "ip"),)).build()


def test_a_format_with_no_client_mapped_is_refused_when_it_is_built() -> None:
    with pytest.raises(JsonFormatError, match="client_ip"):
        JsonFormatSpec(name="no-client", fields=(("timestamp", "ts"),)).build()


def test_a_field_that_is_not_in_the_schema_is_refused_by_name() -> None:
    with pytest.raises(JsonFormatError, match="stauts"):
        JsonFormatSpec(
            name="typo", fields=(("timestamp", "t"), ("client_ip", "ip"), ("stauts", "status"))
        ).build()


# -- travelling ------------------------------------------------------------


def test_a_json_format_survives_the_round_trip_through_json() -> None:
    """It has to reach a worker and a case exactly as it left, like any other
    kind. This is the test that says the stage-1 shape was general enough."""
    restored = spec_from_dict(json.loads(json.dumps(spec_to_dict(MAPPED))))

    assert restored == MAPPED


def test_the_mapping_is_written_as_an_object_a_person_can_edit() -> None:
    """Pairs in a list would round-trip just as well and be unreadable in the
    file, which is meant to be openable in an editor."""
    written = spec_to_dict(MAPPED)

    assert written["fields"]["client_ip"] == "remote_addr"


def test_a_logformat_spec_still_round_trips_beside_it() -> None:
    from zodiarc.parsers.apache import COMBINED
    from zodiarc.parsers.spec import LogFormatSpec

    spec = LogFormatSpec(name="site", directive=COMBINED, description="note")

    assert spec_from_dict(json.loads(json.dumps(spec_to_dict(spec)))) == spec


# -- guessing the mapping --------------------------------------------------


def test_the_usual_key_names_are_guessed_from_one_sample_line() -> None:
    """JSON keys are self-describing in a way a positional format's are not, so
    a guess here is worth making — and the reader sees it before it is saved."""
    guessed = dict(guess_mapping(json.loads(line())))

    assert guessed["timestamp"] == "time"
    assert guessed["client_ip"] == "remote_addr"
    assert guessed["status"] == "status"
    assert guessed["user_agent"] == "http_user_agent"


def test_a_nested_sample_is_guessed_by_path() -> None:
    guessed = dict(guess_mapping({"ts": "2024-05-01T09:00:45Z", "client": {"ip": "203.0.113.5"}}))

    assert guessed["client_ip"] == "client.ip"


def test_a_key_nothing_recognises_is_left_out_rather_than_guessed_at() -> None:
    """A wrong guess is worse than none: the reader accepts it, and finds out
    at ingest when every line is quarantined."""
    guessed = dict(guess_mapping({"quux": "203.0.113.5", "time": "2024-05-01T09:00:45Z"}))

    assert "client_ip" not in guessed


def test_guessing_never_maps_two_of_our_fields_to_one_key() -> None:
    guessed = guess_mapping(json.loads(line()))

    ours = [name for name, _theirs in guessed]
    assert len(ours) == len(set(ours))


def test_a_key_whose_leaf_is_a_generic_word_is_matched_on_its_parent() -> None:
    """ECS and the shapes that copy it write `user_agent.original`, where the
    leaf says nothing and the parent says everything. Matched on the leaf alone
    the guess silently drops the field, and the reader has to know it did."""
    guessed = dict(
        guess_mapping(
            {
                "@timestamp": "2024-05-01T09:00:45Z",
                "client": {"ip": "203.0.113.5"},
                "user_agent": {"original": "curl/8.4.0"},
                "url": {"original": "/admin"},
            }
        )
    )

    assert guessed["user_agent"] == "user_agent.original"
    assert guessed["timestamp"] == "@timestamp"


def test_a_whole_dotted_path_is_matched_when_it_spells_a_field_name() -> None:
    guessed = dict(guess_mapping({"ts": "2024-05-01T09:00:45Z", "client_ip": "203.0.113.5"}))

    assert guessed["client_ip"] == "client_ip"


# -- values that are not the shape the schema wants ------------------------


def test_a_boolean_where_a_number_belongs_is_absent_rather_than_one() -> None:
    """`True` is an `int` in Python and would be stored as a status of 1, which
    is a number no HTTP response ever has and nothing downstream would query."""
    event = MAPPED.build().parse_line(line(status=True), REF)

    assert event is not None
    assert event.status is None


def test_a_float_byte_count_is_rounded_rather_than_refused() -> None:
    """Some pipelines write every number as a float."""
    event = MAPPED.build().parse_line(line(body_bytes_sent=1400.0), REF)

    assert event is not None
    assert event.bytes_sent == 1400


def test_a_byte_count_that_is_not_a_number_costs_that_field_only() -> None:
    event = MAPPED.build().parse_line(line(body_bytes_sent="unknown"), REF)

    assert event is not None
    assert event.bytes_sent is None
    assert event.status == 404


def test_a_boolean_where_the_time_belongs_refuses_the_line() -> None:
    assert MAPPED.build().parse_line(line(time=True), REF) is None


def test_epoch_microseconds_are_told_apart_too() -> None:
    """Some pipelines write microseconds. Read as seconds it is the year
    56,000,000 — far enough out that nothing sorts near it ever again."""
    event = MAPPED.build().parse_line(line(time=1714554045123456), REF)

    assert event is not None
    assert event.timestamp.year == 2024


@pytest.mark.parametrize("written", [1714554045123456789, "1714554045123456789"])
def test_epoch_nanoseconds_are_told_apart_as_well(written: int | str) -> None:
    """Cloudflare Logpush writes `EdgeStartTimestamp` in nanoseconds unless told
    otherwise. Read as microseconds that is the year 56,000, which no clock can
    hold, and the whole log was refused over it."""
    event = MAPPED.build().parse_line(line(time=written), REF)

    assert event is not None
    assert event.timestamp.year == 2024
    assert event.timestamp.hour == 9


@pytest.mark.parametrize("written", [1e300, 10**25, 10**400, "1e300", float("inf"), "nan"])
def test_a_number_no_clock_could_mean_refuses_the_line_not_the_log(written: object) -> None:
    """One line with a number like this raised out of the parser, and ingest
    stopped there: every other line of the log went with it."""
    assert MAPPED.build().parse_line(line(time=written), REF) is None


def test_a_far_future_second_is_read_the_same_on_every_platform() -> None:
    """Windows' clock stops at the year 3000 and Linux's does not, so the same
    log used to read on one and raise on the other."""
    event = MAPPED.build().parse_line(line(time=40_000_000_000), REF)

    assert event is not None
    assert event.timestamp.year == 3237


def test_a_time_the_given_format_does_not_fit_is_not_guessed_at_instead() -> None:
    """The reader said what this field is. Quietly reading it some other way
    would make a pattern that does not work look as though it does."""
    spec = JsonFormatSpec(
        name="told",
        fields=(("timestamp", "time"), ("client_ip", "remote_addr")),
        time_format="%d/%b/%Y %H:%M:%S %z",
    )

    assert spec.build().parse_line(line(time="2024-05-01T09:00:45Z"), REF) is None


# -- request lines that are not request lines ------------------------------


def test_a_two_part_request_line_is_read_without_a_protocol() -> None:
    """HTTP/0.9 and a good deal of scanner traffic."""
    event = MAPPED.build().parse_line(line(request="GET /admin"), REF)

    assert event is not None
    assert event.method == "GET"
    assert event.path == "/admin"
    assert event.protocol is None


def test_a_request_line_that_will_not_split_is_kept_as_evidence() -> None:
    """A TLS handshake sent to a plaintext port, a deliberately corrupted verb.
    Routine in attack traffic and itself a signal, so the line is kept rather
    than quarantined — with the raw text beside the event."""
    event = MAPPED.build().parse_line(line(request="\x16\x03\x01"), REF)

    assert event is not None
    assert event.method is None
    assert event.extra["malformed_request_line"] == "\x16\x03\x01"


def test_an_empty_time_string_refuses_the_line() -> None:
    """A pipeline that writes `""` rather than omitting the key. Without a time
    there is no event, the same as if the key were absent."""
    assert MAPPED.build().parse_line(line(time="   "), REF) is None


# -- where the path ends, and the client's port ------------------------------

SPLIT = JsonFormatSpec(
    name="split",
    fields=(("timestamp", "ts"), ("client_ip", "ip"), ("method", "verb"), ("path", "uri")),
)

URL = JsonFormatSpec(
    name="url",
    fields=(("timestamp", "ts"), ("client_ip", "ip"), ("method", "verb"), ("url", "requestUrl")),
)


def request(**fields: object) -> str:
    return json.dumps({"ts": "2024-05-01T09:00:45Z", "ip": "203.0.113.5", "verb": "GET", **fields})


def test_a_path_that_carries_its_query_is_split_where_a_request_line_is() -> None:
    """Caddy's `request.uri`, Traefik's `RequestPath` and Cloudflare's
    `ClientRequestURI` hold the query as well. Left inside the path it is a
    query no query rule reads: on the shopfront excerpt that hid four SSRF
    attempts and 135 rule matches."""
    event = SPLIT.build().parse_line(request(uri="/search?q=oak&page=2"), REF)

    assert event is not None
    assert (event.path, event.query) == ("/search", "q=oak&page=2")


def test_an_absolute_target_is_kept_as_it_was_sent() -> None:
    """A proxy probe sends the whole URL, Caddy logs it that way, and an Apache
    log keeps it too. It is a signal in itself, so only the query comes off."""
    event = SPLIT.build().parse_line(request(uri="http://evil.example/probe?x=1"), REF)

    assert event is not None
    assert (event.path, event.query) == ("http://evil.example/probe", "x=1")


def test_a_mapped_query_is_never_replaced_by_one_found_in_the_path() -> None:
    spec = JsonFormatSpec(name="both", fields=(*SPLIT.fields, ("query", "args")))

    event = spec.build().parse_line(request(uri="/a?b", args="c=d"), REF)

    assert event is not None
    assert (event.path, event.query) == ("/a?b", "c=d")


def test_a_whole_url_is_read_as_its_host_path_and_query() -> None:
    """Google's `requestUrl` is "the scheme (http, https), the host name, the
    path and the query portion", and this is the example Google gives."""
    event = URL.build().parse_line(
        request(requestUrl="http://example.com/some/info?color=red"), REF
    )

    assert event is not None
    assert (event.host, event.path, event.query) == ("example.com", "/some/info", "color=red")


def test_a_url_with_nothing_after_its_host_is_the_root() -> None:
    event = URL.build().parse_line(request(requestUrl="https://example.com:8443"), REF)

    assert event is not None
    assert (event.host, event.path, event.query) == ("example.com:8443", "/", None)


def test_a_mapped_host_outranks_the_one_inside_the_url() -> None:
    spec = JsonFormatSpec(name="url-host", fields=(*URL.fields, ("host", "h")))

    event = spec.build().parse_line(
        request(requestUrl="http://10.0.0.5/a", h="shop.example.com"), REF
    )

    assert event is not None
    assert (event.host, event.path) == ("shop.example.com", "/a")


def test_a_url_that_is_not_absolute_is_read_like_a_path() -> None:
    event = URL.build().parse_line(request(requestUrl="/a?b=c"), REF)

    assert event is not None
    assert (event.host, event.path, event.query) == (None, "/a", "b=c")


def test_a_url_key_is_guessed_as_a_url() -> None:
    """ECS writes `url.original` and Google `requestUrl`. Read as a path, a
    whole URL would keep its scheme and host in front of every path rule."""
    assert dict(guess_mapping({"requestUrl": "http://example.com/"}))["url"] == "requestUrl"
    assert dict(guess_mapping({"url": {"original": "/a?b=c"}}))["url"] == "url.original"


@pytest.mark.parametrize(
    ("written", "address", "port"),
    [
        ("10.0.0.1:80", "10.0.0.1", "80"),
        ("[2001:db8::1]:443", "2001:db8::1", "443"),
        ("[2001:db8::1]", "2001:db8::1", None),
        # Bare IPv6 could end in a port or in its own last group: never split.
        ("2001:db8::1:443", "2001:db8::1:443", None),
        ("::ffff:203.0.113.5", "::ffff:203.0.113.5", None),
        ("203.0.113.5", "203.0.113.5", None),
    ],
)
def test_a_client_written_with_a_port_is_the_address_alone(
    written: str, address: str, port: str | None
) -> None:
    """Google's `remoteIp` "can include port information". Kept whole, every
    new port is a new client, and one visitor splits into many."""
    event = SPLIT.build().parse_line(request(ip=written, uri="/"), REF)

    assert event is not None
    assert event.client_ip == address
    assert event.extra.get("client_port") == port
