"""Every format logarc ships with, against a real line of the log it is named for.

A built-in that does not read the logs it is named for is worse than an absent
one. Absent, the reader writes their own and finds out in the editor; wrong,
they get a case that looks complete and is not — which the quarantine notice
calls this tool's worst failure mode.

So this file is the gate: a format may not be added to `parsers.builtins`
without a sample here, and the sample has to be a line the product actually
writes rather than one shaped to fit.
"""

from __future__ import annotations

import json

import pytest

from logarc.core.evidence import EvidenceRef
from logarc.parsers.builtins import BUILT_INS
from logarc.parsers.registry import available_formats, detect_format, get_spec

REF = EvidenceRef(source_file_id="f", line_no=1)

#: One real line per built-in, and what reading it has to yield. Several lines
#: where the format needs a header to know its own columns.
SAMPLES: dict[str, tuple[list[str], dict[str, object]]] = {
    "apache-vhost-combined": (
        [
            "shop.example.com:443 203.0.113.5 - - [01/May/2024:09:00:45 +0000] "
            '"GET /admin/.env HTTP/1.1" 404 0 "-" "curl/8.4.0"'
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "host": "shop.example.com",
        },
    ),
    "apache-combined-io": (
        [
            "203.0.113.5 - - [01/May/2024:09:00:45 +0000] "
            '"GET /admin/.env HTTP/1.1" 404 0 "-" "curl/8.4.0" 412 291'
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    "nginx-combined-forwarded": (
        [
            "203.0.113.5 - - [01/May/2024:09:00:45 +0000] "
            '"GET /admin/.env HTTP/1.1" 404 0 "-" "curl/8.4.0" "198.51.100.9" 0.123'
        ],
        {"client_ip": "203.0.113.5", "path": "/admin/.env", "status": 404},
    ),
    "apache-combined": (
        [
            "203.0.113.5 - - [01/May/2024:09:00:45 +0000] "
            '"GET /admin/.env HTTP/1.1" 404 0 "https://shop.example.com/" "curl/8.4.0"'
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "referer": "https://shop.example.com/",
        },
    ),
    "apache-vhost-common": (
        [
            "shop.example.com 203.0.113.5 - - [01/May/2024:09:00:45 +0000] "
            '"GET /admin/.env HTTP/1.1" 404 0'
        ],
        {"client_ip": "203.0.113.5", "path": "/admin/.env", "host": "shop.example.com"},
    ),
    "apache-common": (
        ['203.0.113.5 - - [01/May/2024:09:00:45 +0000] "GET /admin/.env HTTP/1.1" 404 0'],
        {"client_ip": "203.0.113.5", "path": "/admin/.env", "status": 404},
    ),
    "nginx-json": (
        [
            json.dumps(
                {
                    "time_local": "01/May/2024:09:00:45 +0000",
                    "remote_addr": "203.0.113.5",
                    "request": "GET /admin/.env HTTP/1.1",
                    "status": "404",
                    "body_bytes_sent": "0",
                    "http_referer": "-",
                    "http_user_agent": "curl/8.4.0",
                }
            )
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    "caddy-json": (
        [
            json.dumps(
                {
                    "level": "info",
                    "ts": 1714554045.123,
                    "logger": "http.log.access",
                    "msg": "handled request",
                    "request": {
                        "remote_ip": "203.0.113.5",
                        "proto": "HTTP/2.0",
                        "method": "GET",
                        "host": "shop.example.com",
                        "uri": "/admin/.env",
                        "headers": {"User-Agent": ["curl/8.4.0"]},
                    },
                    "status": 404,
                    "size": 0,
                }
            )
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "host": "shop.example.com",
            "user_agent": "curl/8.4.0",
        },
    ),
    "traefik-json": (
        [
            json.dumps(
                {
                    "ClientHost": "203.0.113.5",
                    "DownstreamContentSize": 0,
                    "DownstreamStatus": 404,
                    "RequestHost": "shop.example.com",
                    "RequestMethod": "GET",
                    "RequestPath": "/admin/.env",
                    "RequestProtocol": "HTTP/1.1",
                    "StartUTC": "2024-05-01T09:00:45.123456789Z",
                    "request_User-Agent": "curl/8.4.0",
                }
            )
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "host": "shop.example.com",
        },
    ),
    "cloudflare-json": (
        [
            json.dumps(
                {
                    "ClientIP": "203.0.113.5",
                    "ClientRequestHost": "shop.example.com",
                    "ClientRequestMethod": "GET",
                    "ClientRequestURI": "/admin/.env",
                    "ClientRequestReferer": "",
                    "ClientRequestUserAgent": "curl/8.4.0",
                    "EdgeResponseBytes": 0,
                    "EdgeResponseStatus": 404,
                    "EdgeStartTimestamp": "2024-05-01T09:00:45Z",
                }
            )
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    "gcp-http-json": (
        [
            json.dumps(
                {
                    "timestamp": "2024-05-01T09:00:45.123456Z",
                    "severity": "WARNING",
                    "httpRequest": {
                        "requestMethod": "GET",
                        "requestUrl": "/admin/.env",
                        "status": 404,
                        "responseSize": "0",
                        "userAgent": "curl/8.4.0",
                        "remoteIp": "203.0.113.5",
                        "protocol": "HTTP/1.1",
                    },
                }
            )
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    "ecs-http": (
        [
            json.dumps(
                {
                    "@timestamp": "2024-05-01T09:00:45.123Z",
                    "client": {"ip": "203.0.113.5"},
                    "url": {"path": "/admin/.env", "query": "id=1", "domain": "shop.example.com"},
                    "http": {
                        "request": {"method": "GET"},
                        "response": {"status_code": 404, "body": {"bytes": 0}},
                    },
                    "user_agent": {"original": "curl/8.4.0"},
                }
            )
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "query": "id=1",
            "status": 404,
            "host": "shop.example.com",
            "user_agent": "curl/8.4.0",
        },
    ),
    "iis-w3c": (
        [
            "#Software: Microsoft Internet Information Services 10.0",
            "#Version: 1.0",
            "#Date: 2024-05-01 09:00:45",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username"
            " c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken",
            "2024-05-01 09:00:45 10.0.0.1 GET /admin/.env - 80 - 203.0.113.5"
            " curl/8.4.0 - 404 0 0 15",
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    "cloudfront": (
        [
            "#Version: 1.0",
            "#Fields: date\ttime\tx-edge-location\tsc-bytes\tc-ip\tcs-method\tcs(Host)"
            "\tcs-uri-stem\tsc-status\tcs(Referer)\tcs(User-Agent)\tcs-uri-query",
            "2024-05-01\t09:00:45\tSFO5-C1\t0\t203.0.113.5\tGET\tshop.example.com"
            "\t/admin/.env\t404\t-\tcurl/8.4.0\t-",
        ],
        {
            "client_ip": "203.0.113.5",
            "path": "/admin/.env",
            "status": 404,
            "host": "shop.example.com",
            "user_agent": "curl/8.4.0",
        },
    ),
}


def test_every_built_in_has_a_sample_of_the_log_it_is_named_for() -> None:
    """The gate. A format added without one would be shipped untried, and the
    reader would be the one to find out."""
    assert {spec.name for spec in BUILT_INS} == set(SAMPLES)


@pytest.mark.parametrize("name", list(SAMPLES))
def test_a_built_in_reads_the_log_it_is_named_for(name: str) -> None:
    lines, expected = SAMPLES[name]
    spec = get_spec(name)
    assert spec is not None

    parser = spec.resolved(lines).build()
    rows = [line for line in lines if not parser.is_metadata(line)]
    event = parser.parse_line(rows[-1], REF)

    assert event is not None, f"{name} did not read its own sample"
    for field, value in expected.items():
        assert getattr(event, field) == value, field


@pytest.mark.parametrize("name", list(SAMPLES))
def test_a_built_in_is_the_one_detection_picks_for_its_own_log(name: str) -> None:
    """Reading it is not enough: with fourteen of them, the one that reads a log
    best has to be the one auto-detection chooses. A format that reads its log
    and loses to another is a format nobody will ever see used."""
    lines, _expected = SAMPLES[name]

    found = detect_format(lines * 4)

    assert found is not None, f"nothing detected {name}"
    assert found.name == name, f"{name}'s own log was detected as {found.name}"


def test_the_built_ins_are_all_registered_in_their_declared_order() -> None:
    """Order is preference order, and detection falls back to it on a tie."""
    names = [spec.name for spec in BUILT_INS]

    assert available_formats()[: len(names)] == names


def test_a_more_specific_format_comes_before_the_one_it_extends() -> None:
    """Not cosmetic: on a tie the earlier one wins, so getting this backwards
    reads a log with a poorer parser and drops fields silently."""
    order = [spec.name for spec in BUILT_INS]

    assert order.index("apache-combined-io") < order.index("apache-combined")
    assert order.index("nginx-combined-forwarded") < order.index("apache-combined-io"), (
        "an nginx forwarded line satisfies apache-combined-io too — io's two "
        "trailing counts are bare fields and match the quoted forwarded-for "
        "and the request time. The other way round is not ambiguous."
    )
    assert order.index("apache-combined") < order.index("apache-common")
    assert order.index("apache-vhost-combined") < order.index("apache-vhost-common")


def test_every_built_in_says_what_it_is_for() -> None:
    """`logarc formats` lists them all; a name with no description leaves the
    reader guessing which of fourteen is theirs."""
    for spec in BUILT_INS:
        assert spec.description, spec.name
