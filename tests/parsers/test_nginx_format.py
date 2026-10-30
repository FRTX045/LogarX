"""An nginx `log_format`, pasted as it is written in nginx's own config.

The lines are nginx 1.30.6's, written in Docker on 2026-10-25 by a server
configured with exactly the three statements below, and copied as they came
out. The statements are copied from that config too, quoting and all.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from zodiarc.core.evidence import EvidenceRef
from zodiarc.parsers.logformat import LogFormatError, LogFormatParser
from zodiarc.parsers.nginx import looks_like_nginx
from zodiarc.parsers.registry import get_spec

REF = EvidenceRef(source_file_id="f", line_no=1)

#: The packaged default, as nginx.org's packages and the Docker image ship it.
MAIN = (
    "log_format  main  '$remote_addr - $remote_user [$time_local] \"$request\" '\n"
    "                  '$status $body_bytes_sent \"$http_referer\" '\n"
    '                  \'"$http_user_agent" "$http_x_forwarded_for"\';'
)

#: The timing format nginx's own blog put about, copied into many configs.
TIMED = (
    'log_format timed \'$remote_addr - $remote_user [$time_local] "$request" $status'
    ' $body_bytes_sent "$http_referer" "$http_user_agent" rt=$request_time'
    ' uct="$upstream_connect_time" uht="$upstream_header_time"'
    ' urt="$upstream_response_time"\';'
)

#: Double-quoted, so its own quotes are escaped, and one variable in braces.
ISO = (
    r'log_format iso "$time_iso8601 $remote_addr ${host} \"$request_method $request_uri'
    r' $server_protocol\" $status $body_bytes_sent $request_time";'
)

MAIN_LINES = [
    '10.244.0.1 - - [25/Oct/2026:20:42:30 +0000] "GET / HTTP/1.1" 200 158 "-" "curl/8.21.0" "-"',
    '10.244.0.1 - - [25/Oct/2026:20:42:30 +0000] "GET /search?q=oak&page=2 HTTP/1.1" 200 260'
    ' "https://shop.example/" "Mozilla/5.0 (X11; Linux x86_64)" "198.51.100.4"',
    r'10.244.0.1 - - [25/Oct/2026:20:42:31 +0000] "GET /login?user=admin%27-- HTTP/1.1" 200 186'
    r' "-" "sqlmap/1.8 \x22probe\x22" "-"',
    '10.244.0.1 - - [25/Oct/2026:20:42:31 +0000] "POST /api/cart HTTP/1.1" 200 186 "-"'
    ' "curl/8.21.0" "-"',
]

TIMED_LINE = (
    '10.244.0.1 - - [25/Oct/2026:20:42:30 +0000] "GET /search?q=oak&page=2 HTTP/1.1" 200 260'
    ' "https://shop.example/" "Mozilla/5.0 (X11; Linux x86_64)" rt=0.021 uct="0.000"'
    ' uht="0.022" urt="0.022"'
)

ISO_LINE = (
    '2026-10-25T20:42:30+00:00 10.244.0.1 127.0.0.1 "GET /search?q=oak&page=2 HTTP/1.1" 200 260'
    " 0.021"
)

FIELDS = (
    "timestamp",
    "client_ip",
    "method",
    "path",
    "query",
    "protocol",
    "status",
    "bytes_sent",
    "referer",
    "user_agent",
    "host",
    "extra",
)


def _read(log_format: str, line: str):
    event = LogFormatParser(log_format).parse_line(line, REF)
    assert event is not None, f"{log_format!r} refused {line!r}"
    return event


# -- reading what nginx wrote -------------------------------------------------


@pytest.mark.parametrize("line", MAIN_LINES)
def test_the_packaged_main_reads_exactly_as_the_built_in_does(line: str) -> None:
    """The same format, pasted or built in, has to read the same line the same
    way, field for field."""
    built_in = get_spec("nginx-main")
    assert built_in is not None
    expected = built_in.build().parse_line(line, REF)

    pasted = _read(MAIN, line)

    assert expected is not None
    for field in FIELDS:
        assert getattr(pasted, field) == getattr(expected, field), field


def test_the_timing_format_keeps_its_upstream_times() -> None:
    event = _read(TIMED, TIMED_LINE)

    assert (event.path, event.query, event.status) == ("/search", "q=oak&page=2", 200)
    assert event.referer == "https://shop.example/"
    assert event.extra["duration_s"] == "0.021"
    assert event.extra["env_upstream_connect_time"] == "0.000"
    assert event.extra["env_upstream_response_time"] == "0.022"


def test_a_double_quoted_statement_with_braces_and_the_request_uri() -> None:
    """`$request_uri` is the path and the query as sent; `${host}` is `$host`."""
    event = _read(ISO, ISO_LINE)

    assert event.timestamp == datetime(2026, 10, 25, 20, 42, 30, tzinfo=UTC)
    assert (event.method, event.path, event.query) == ("GET", "/search", "q=oak&page=2")
    assert event.protocol == "HTTP/1.1"
    assert event.host == "127.0.0.1"
    assert event.status == 200


def test_nginx_s_escaping_is_undone() -> None:
    """nginx writes a `"` the client sent as `\\x22`."""
    event = _read(MAIN, MAIN_LINES[2])

    assert event.user_agent == 'sqlmap/1.8 "probe"'


# -- the shapes a format is pasted in ------------------------------------------

#: `main`'s format on its own: the three strings joined, as nginx joins them.
MAIN_FORMAT = (
    '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent'
    ' "$http_referer" "$http_user_agent" "$http_x_forwarded_for"'
)


@pytest.mark.parametrize(
    "pasted",
    [
        MAIN_FORMAT,
        "'$remote_addr - $remote_user [$time_local] \"$request\" '"
        " '$status $body_bytes_sent \"$http_referer\" '"
        ' \'"$http_user_agent" "$http_x_forwarded_for"\'',
        MAIN.replace("main  '", "main escape=default '") + "  # the packaged default",
    ],
    ids=["the format alone", "its strings alone", "escape=default and a comment"],
)
def test_a_format_is_read_however_it_is_pasted(pasted: str) -> None:
    event = _read(pasted, MAIN_LINES[1])

    assert event.client_ip == "10.244.0.1"
    assert event.user_agent == "Mozilla/5.0 (X11; Linux x86_64)"
    assert event.extra["req_header_x_forwarded_for"] == "198.51.100.4"


def test_a_format_that_starts_with_a_quote_of_its_own_is_not_unquoted() -> None:
    """Constructed. Quoted strings are read as a config's only when every piece
    is one; this format's first quote is part of what nginx writes."""
    event = _read(
        '"$request" $remote_addr [$time_local] $status',
        '"GET /a HTTP/1.1" 10.244.0.1 [25/Oct/2026:20:42:30 +0000] 200',
    )

    assert (event.client_ip, event.path, event.status) == ("10.244.0.1", "/a", 200)


def test_a_time_local_outside_brackets_is_read() -> None:
    """Constructed from the first `main` line, with the brackets left out."""
    event = _read(
        '$remote_addr $time_local "$request" $status',
        '10.244.0.1 25/Oct/2026:20:42:30 +0000 "GET / HTTP/1.1" 200',
    )

    assert event.timestamp == datetime(2026, 10, 25, 20, 42, 30, tzinfo=UTC)
    assert event.status == 200


def test_a_percent_sign_in_an_nginx_format_is_a_percent_sign() -> None:
    event = _read(
        '$remote_addr [$time_local] "$request" $status 100%',
        '10.244.0.1 [25/Oct/2026:20:42:30 +0000] "GET / HTTP/1.1" 200 100%',
    )

    assert event.status == 200


# -- refused, with the way out ----------------------------------------------------


@pytest.mark.parametrize(
    "pasted",
    [
        'log_format j escape=json \'{"t":"$time_iso8601","ip":"$remote_addr"}\';',
        '\'{"t":"$time_iso8601","ip":"$remote_addr"}\'',
    ],
    ids=["escape=json", "a JSON template"],
)
def test_a_json_format_is_sent_to_the_json_kind(pasted: str) -> None:
    """Its log is JSON, which the JSON kind reads from the log itself. Named as
    the window offers it: there is no command to run."""
    with pytest.raises(LogFormatError, match="New → JSON"):
        LogFormatParser(pasted)


def test_a_format_with_no_time_is_refused_naming_the_variables() -> None:
    with pytest.raises(LogFormatError, match=r"\$time_local"):
        LogFormatParser('$remote_addr "$request" $status')


def test_a_format_dated_only_by_msec_says_so() -> None:
    with pytest.raises(LogFormatError, match=r"\$msec"):
        LogFormatParser('$msec $remote_addr "$request" $status')


def test_a_format_with_no_remote_addr_is_refused() -> None:
    """A forwarded-for header is the client's to write, and is never the
    client in a format that could have written the connection's address."""
    with pytest.raises(LogFormatError, match=r"\$remote_addr"):
        LogFormatParser('$http_x_forwarded_for [$time_local] "$request" $status')


# -- telling the two apart --------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "nginx"),
    [
        (MAIN, True),
        (MAIN_FORMAT, True),
        ('%h %l %u %t "%r" %>s %b', False),
        ('%h $ %t "%r" %>s %b', False),
        ("plain text", False),
    ],
)
def test_nginx_is_told_from_apache(text: str, nginx: bool) -> None:
    assert looks_like_nginx(text) is nginx


def test_an_apache_directive_with_a_dollar_sign_is_still_apache() -> None:
    event = _read(
        '%h $ %t "%r" %>s %b',
        '203.0.113.5 $ [01/May/2024:09:00:45 +0000] "GET / HTTP/1.1" 200 5',
    )

    assert event.client_ip == "203.0.113.5"
