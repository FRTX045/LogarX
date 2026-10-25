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

from logarc.core.event import NormalizedEvent
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
    # The three below were written by the servers themselves on 2026-10-25, in
    # Docker: the official nginx 1.30.6 image untouched, Traefik 3.7.16, and
    # nginx 1.30.6 running ingress-nginx's own `logFormatUpstream` with the
    # variables its template sets. Copied as they came out.
    "nginx-main": (
        [
            "172.17.0.1 - - [25/Oct/2026:04:37:41 +0000] "
            '"GET /admin/.env HTTP/1.1" 404 153 "-" "curl/8.4.0" "198.51.100.4"'
        ],
        {
            "client_ip": "172.17.0.1",
            "path": "/admin/.env",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    "ingress-nginx": (
        [
            "10.244.0.1 - - [25/Oct/2026:04:38:06 +0000] "
            '"GET /api/items?id=2 HTTP/1.1" 200 3 "-" '
            '"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/144.0" 142 0.000 '
            "[default-web-80] [] 10.244.0.15:80 3 0.000 200 c1a81653340721f6859a87a3230997d6"
        ],
        {
            "client_ip": "10.244.0.1",
            "path": "/api/items",
            "query": "id=2",
            "status": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/144.0",
        },
    ),
    "traefik-common": (
        [
            "10.244.0.1 - - [25/Oct/2026:04:39:15 +0000] "
            '"GET /login?user=admin%27-- HTTP/1.1" 200 392 "-" "sqlmap/1.8 \\"probe\\"" '
            '5 "web@file" "http://10.244.0.20:80" 21ms'
        ],
        {
            "client_ip": "10.244.0.1",
            "path": "/login",
            "query": "user=admin%27--",
            "status": 200,
            # Traefik escapes a quote inside a quoted field as `\"`.
            "user_agent": 'sqlmap/1.8 "probe"',
        },
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
    # Written by Caddy 2.11.7 and Traefik 3.7.16 (`--accesslog.format=json`,
    # User-Agent kept) on 2026-10-25, and copied as they came out. Both hold the
    # query inside the path field, which the earlier hand-made samples did not.
    "caddy-json": (
        [
            '{"level":"info","ts":1792912714.3353026,"logger":"http.log.access.log0",'
            '"msg":"handled request","request":{"remote_ip":"172.17.0.1",'
            '"remote_port":"58800","client_ip":"172.17.0.1","proto":"HTTP/1.1",'
            '"method":"GET","host":"127.0.0.1:18090","uri":"/search?q=oak&page=2",'
            '"headers":{"User-Agent":["curl/8.4.0"],"Accept":["*/*"],'
            '"Referer":["http://example.com/"]}},"bytes_read":0,"user_id":"",'
            '"duration":0.000093507,"size":2,"status":200,"resp_headers":'
            '{"Server":["Caddy"],"Content-Type":["text/plain; charset=utf-8"]}}'
        ],
        {
            "client_ip": "172.17.0.1",
            "path": "/search",
            "query": "q=oak&page=2",
            "status": 200,
            "host": "127.0.0.1:18090",
            "user_agent": "curl/8.4.0",
            "referer": "http://example.com/",
        },
    ),
    "traefik-json": (
        [
            '{"ClientAddr":"10.244.0.1:44624","ClientHost":"10.244.0.1","ClientPort":"44624",'
            '"ClientUsername":"-","DownstreamContentSize":382,"DownstreamStatus":200,'
            '"Duration":21730853,"OriginContentSize":382,"OriginDuration":21698943,'
            '"OriginStatus":200,"Overhead":31910,"RequestAddr":"127.0.0.1:18082",'
            '"RequestContentSize":0,"RequestCount":5,"RequestHost":"127.0.0.1",'
            '"RequestMethod":"GET","RequestPath":"/search?q=oak\\u0026page=2",'
            '"RequestPort":"18082","RequestProtocol":"HTTP/1.1","RequestScheme":"http",'
            '"RetryAttempts":0,"RouterName":"web@file","ServiceAddr":"10.244.0.20:80",'
            '"ServiceName":"whoami@file","ServiceURL":"http://10.244.0.20:80",'
            '"StartLocal":"2026-10-25T07:19:18.367248419Z",'
            '"StartUTC":"2026-10-25T07:19:18.367248419Z","entryPointName":"web",'
            '"level":"info","msg":"","request_User-Agent":"curl/8.4.0",'
            '"time":"2026-10-25T07:19:18Z"}'
        ],
        {
            "client_ip": "10.244.0.1",
            "path": "/search",
            "query": "q=oak&page=2",
            "status": 200,
            "host": "127.0.0.1",
            "user_agent": "curl/8.4.0",
        },
    ),
    # Cloudflare's `ClientRequestURI` is "the full path and query string of the
    # requested URL" (its Logpush field reference), so the sample carries both.
    "cloudflare-json": (
        [
            json.dumps(
                {
                    "ClientIP": "203.0.113.5",
                    "ClientRequestHost": "shop.example.com",
                    "ClientRequestMethod": "GET",
                    "ClientRequestURI": "/admin/.env?debug=1",
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
            "query": "debug=1",
            "status": 404,
            "user_agent": "curl/8.4.0",
        },
    ),
    # Google's `requestUrl` is "the scheme (http, https), the host name, the path
    # and the query portion", and `remoteIp` "can include port information"; the
    # two values here are the examples Google's LogEntry reference gives.
    "gcp-http-json": (
        [
            json.dumps(
                {
                    "timestamp": "2024-05-01T09:00:45.123456Z",
                    "severity": "WARNING",
                    "httpRequest": {
                        "requestMethod": "GET",
                        "requestUrl": "http://example.com/some/info?color=red",
                        "status": 404,
                        "responseSize": "0",
                        "userAgent": "curl/8.4.0",
                        "remoteIp": "10.0.0.1:80",
                        "protocol": "HTTP/1.1",
                    },
                }
            )
        ],
        {
            "client_ip": "10.0.0.1",
            "host": "example.com",
            "path": "/some/info",
            "query": "color=red",
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
    """Reading it is not enough: with this many of them, the one that reads a log
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
    assert order.index("nginx-main") < order.index("apache-combined-io"), (
        "behind two proxies nginx-main's forwarded-for is `\"a, b\"`, and io's two "
        "bare counts match its two halves, quotes and all."
    )


def test_every_built_in_says_what_it_is_for() -> None:
    """`logarc formats` lists them all; a name with no description leaves the
    reader guessing which of them is theirs."""
    for spec in BUILT_INS:
        assert spec.description, spec.name


def _read(name: str, line: str) -> NormalizedEvent:
    spec = get_spec(name)
    assert spec is not None
    event = spec.build().parse_line(line, REF)
    assert event is not None, f"{name} refused {line!r}"
    return event


#: Written by nginx running ingress-nginx's log format, as the sample above.
INGRESS_INCIDENT = {
    # The first upstream refused the connection and nginx tried the next one.
    "retried": (
        "10.244.0.1 - - [25/Oct/2026:04:38:06 +0000] "
        '"GET /api/items?id=1 HTTP/1.1" 200 3 "-" '
        '"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/144.0" 142 0.001 '
        "[default-web-80] [] 10.244.0.16:80, 10.244.0.15:80 0, 3 0.000, 0.001 502, 200 "
        "e527b65e1b1bac86c519856c741a8d19",
        {
            "env_upstream_addr": "10.244.0.16:80, 10.244.0.15:80",
            "env_upstream_status": "502, 200",
            "env_req_id": "e527b65e1b1bac86c519856c741a8d19",
        },
    ),
    # The upstream said 404 and a custom error page sent it to the default backend.
    "redirected": (
        "10.244.0.1 - - [25/Oct/2026:04:38:06 +0000] "
        '"GET /shop/gone HTTP/1.1" 404 22 "-" "curl/8.4.0" 87 0.001 [default-shop-80] [] '
        "10.244.0.15:80 : 10.244.0.17:80 0 : 22 0.001 : 0.000 404 : 404 "
        "566786bc6808e17eca8bf893b7b6433a",
        {
            "env_upstream_addr": "10.244.0.15:80 : 10.244.0.17:80",
            "env_upstream_status": "404 : 404",
        },
    ),
    # `$req_id` is the client's own X-Request-ID when it sends one.
    "request id with a space": (
        "10.244.0.1 - - [25/Oct/2026:04:38:06 +0000] "
        '"GET /api/items?id=3 HTTP/1.1" 200 3 "-" "curl/8.4.0" 111 0.000 '
        "[default-web-80] [] 10.244.0.15:80 3 0.000 200 a b",
        {"env_req_id": "a b"},
    ),
    "request id with a comma": (
        "10.244.0.1 - - [25/Oct/2026:04:38:06 +0000] "
        '"GET /api/items?id=4 HTTP/1.1" 200 3 "-" "curl/8.4.0" 116 0.000 '
        "[default-web-80] [] 10.244.0.15:80 3 0.000 200 abc, def",
        {"env_req_id": "abc, def"},
    ),
}


@pytest.mark.parametrize("case", list(INGRESS_INCIDENT))
def test_ingress_nginx_reads_the_lines_an_incident_leaves(case: str) -> None:
    """Retries and error pages are when upstream fields become lists, and the
    request id is whatever the client chose to send. All of them are read, and
    detection still names the format."""
    line, extra = INGRESS_INCIDENT[case]

    event = _read("ingress-nginx", line)

    assert {key: event.extra.get(key) for key in extra} == extra
    found = detect_format([line] * 4)
    assert found is not None
    assert found.name == "ingress-nginx"


def test_traefik_default_log_has_no_user_agent_and_is_still_read() -> None:
    """Traefik drops request headers unless told to keep them, so its default
    log writes `"-" "-"` where the Referer and User-Agent go — written by an
    untouched Traefik 3.7.16 for a request that sent both."""
    line = (
        "10.244.0.1 - - [25/Oct/2026:04:39:12 +0000] "
        '"GET /api/items/7?sort=price HTTP/1.1" 200 523 "-" "-" 2 "web@file" '
        '"http://10.244.0.20:80" 21ms'
    )

    event = _read("traefik-common", line)

    assert event.user_agent is None
    assert event.referer is None
    assert event.extra["env_router_name"] == "web@file"
    assert event.extra["env_service_url"] == "http://10.244.0.20:80"
    assert event.extra["env_duration_ms"] == "21"
    found = detect_format([line] * 4)
    assert found is not None
    assert found.name == "traefik-common"


def test_nginx_main_behind_two_proxies_is_not_read_as_io() -> None:
    """The order the test above checks, shown on the line that needs it."""
    line = (
        "172.17.0.1 - - [25/Oct/2026:04:37:41 +0000] "
        '"GET /wp-login.php HTTP/1.1" 404 153 "-" "curl/8.4.0" "198.51.100.4, 10.0.0.2"'
    )

    found = detect_format([line] * 4)

    assert found is not None
    assert found.name == "nginx-main"
    assert _read("nginx-main", line).extra["req_header_x_forwarded_for"] == (
        "198.51.100.4, 10.0.0.2"
    )


def test_nginx_main_undoes_the_escaping_nginx_wrote() -> None:
    """nginx writes a quote as `\\x22`. Rules match what the client sent."""
    line = (
        "172.17.0.1 - - [25/Oct/2026:04:37:41 +0000] "
        '"GET /search?q=1\\x22or\\x221 HTTP/1.1" 404 153 "-" "sqlmap/1.8 \\x22probe\\x22" "-"'
    )

    event = _read("nginx-main", line)

    assert event.query == 'q=1"or"1'
    assert event.user_agent == 'sqlmap/1.8 "probe"'


#: What the official image prints on stdout before its first request, as
#: `docker logs` hands it back.
NGINX_IMAGE_START = [
    "/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform"
    " configuration",
    "/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/",
    "/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh",
    "10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf",
    "10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in"
    " /etc/nginx/conf.d/default.conf",
    "/docker-entrypoint.sh: Sourcing /docker-entrypoint.d/15-local-resolvers.envsh",
    "/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh",
    "/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh",
    "/docker-entrypoint.sh: Configuration complete; ready for start up",
]


def test_docker_logs_of_the_nginx_image_still_detect_nginx_main() -> None:
    """`docker logs nginx > access.log` keeps the image's start-up messages on
    top. They are not requests and are refused, and the log is still
    recognised by the requests that follow them."""
    lines, _expected = SAMPLES["nginx-main"]
    sample = [*NGINX_IMAGE_START, *(lines * 100)]

    found = detect_format(sample)

    assert found is not None
    assert found.name == "nginx-main"
    assert all(found.parser.parse_line(line, REF) is None for line in NGINX_IMAGE_START)


#: One request, `GET /search?q=oak&page=2`, as each format that carries a path
#: and a query writes it. Caddy's and Traefik's are their real lines above.
SAME_REQUEST: dict[str, list[str]] = {
    "apache-combined": [
        '203.0.113.5 - - [25/Oct/2026:07:19:18 +0000] "GET /search?q=oak&page=2 HTTP/1.1"'
        ' 200 2 "-" "curl/8.4.0"'
    ],
    "traefik-common": [
        '203.0.113.5 - - [25/Oct/2026:07:19:18 +0000] "GET /search?q=oak&page=2 HTTP/1.1"'
        ' 200 2 "-" "curl/8.4.0" 5 "web@file" "http://10.244.0.20:80" 21ms'
    ],
    "nginx-json": [
        json.dumps(
            {
                "time_local": "25/Oct/2026:07:19:18 +0000",
                "remote_addr": "203.0.113.5",
                "request": "GET /search?q=oak&page=2 HTTP/1.1",
                "status": "200",
            }
        )
    ],
    "caddy-json": SAMPLES["caddy-json"][0],
    "traefik-json": SAMPLES["traefik-json"][0],
    "cloudflare-json": [
        json.dumps(
            {
                "ClientIP": "203.0.113.5",
                "ClientRequestMethod": "GET",
                "ClientRequestURI": "/search?q=oak&page=2",
                "EdgeResponseStatus": 200,
                "EdgeStartTimestamp": "2026-10-25T07:19:18Z",
            }
        )
    ],
    "gcp-http-json": [
        json.dumps(
            {
                "timestamp": "2026-10-25T07:19:18Z",
                "httpRequest": {
                    "requestMethod": "GET",
                    "requestUrl": "https://shop.example.com/search?q=oak&page=2",
                    "status": 200,
                    "remoteIp": "203.0.113.5",
                },
            }
        )
    ],
    "ecs-http": [
        json.dumps(
            {
                "@timestamp": "2026-10-25T07:19:18Z",
                "client": {"ip": "203.0.113.5"},
                "url": {"path": "/search", "query": "q=oak&page=2"},
                "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
            }
        )
    ],
    "iis-w3c": [
        "#Fields: date time cs-method cs-uri-stem cs-uri-query c-ip sc-status",
        "2026-10-25 07:19:18 GET /search q=oak&page=2 203.0.113.5 200",
    ],
    "cloudfront": [
        "#Version: 1.0",
        "\t".join(["#Fields: date", "time", "c-ip", "cs-method", "cs-uri-stem", "cs-uri-query"]),
        "\t".join(["2026-10-25", "07:19:18", "203.0.113.5", "GET", "/search", "q=oak&page=2"]),
    ],
}


@pytest.mark.parametrize("name", list(SAME_REQUEST))
def test_one_request_reads_the_same_whichever_format_wrote_it(name: str) -> None:
    """The promise `parsers.base` makes. Broken, it is silent: four of these
    once read `/search?q=oak&page=2` as all path, and no query rule saw it."""
    lines = SAME_REQUEST[name]
    spec = get_spec(name)
    assert spec is not None
    parser = spec.resolved(lines).build()
    event = parser.parse_line([row for row in lines if not parser.is_metadata(row)][-1], REF)

    assert event is not None
    assert (event.method, event.path, event.query) == ("GET", "/search", "q=oak&page=2")
