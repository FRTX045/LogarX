"""The log formats logarc ships with.

Every one of these is ordinary data — the same records a reader writes for
themselves — so nothing here is a special case in the machinery. What makes
them built in is that they are registered at import and cannot be edited: a
case recording `apache-combined` has to keep meaning what it meant.

**Order is preference order.** Detection compares confidence first and falls
back to this order on a tie, so a format carrying more information must come
before the one carrying less. `apache-combined-io` before `apache-combined`,
and both before `apache-common`. Getting that backwards does not fail loudly;
it quietly reads a log with a poorer parser and drops fields nobody misses
until they need them.

**Each of these has a real sample line beside it in the tests, and a test that
it reads that line.** A built-in that does not read the logs it is named for is
worse than an absent one: absent, the reader writes their own; wrong, they get
a case that looks complete. `tests/parsers/test_builtins.py` refuses to let a
format be added here without one.

The proxies at the end of the text group — HAProxy, AWS ALB, Istio, Envoy —
write the client with its port, and are patterns rather than directives. Each
one reads its port off where the format guarantees one is written, so an IPv6
address written bare is never cut. Envoy needed more than that: it writes a
client's quotes unescaped, and its default line has no client address of its
own. How that is read safely is at `_ENVOY`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from logarc.parsers.apache import COMBINED, COMMON, VHOST_COMBINED
from logarc.parsers.spec import (
    ColumnsFormatSpec,
    JsonFormatSpec,
    LogFormatSpec,
    PatternFormatSpec,
)

if TYPE_CHECKING:
    from logarc.parsers.spec import FormatSpec

__all__ = ["BUILT_INS"]


def _apache(name: str, directive: str, description: str) -> LogFormatSpec:
    return LogFormatSpec(name=name, directive=directive, description=description)


def _json(name: str, description: str, **fields: str) -> JsonFormatSpec:
    return JsonFormatSpec(name=name, fields=tuple(fields.items()), description=description)


#: The envelope HAProxy's line arrives in, every part optional and in the order
#: syslog writes them: a priority (`<134>`), RFC 5424's header, an ISO stamp,
#: RFC 3164's stamp (`Feb  6 12:14:14`, day padded), and `host tag[pid]: `.
#: Between them: the seven formats HAProxy writes, and both of rsyslog's file
#: templates.
_HAPROXY_ENVELOPE: Final = (
    r"(?:<\d{1,3}>)?"
    r"(?:1 \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?\]) )?"
    r"(?:\d{4}-\d\d-\d\dT\S+ )?"
    r"(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d )?"
    r"(?:\S+ [^\s:\[]+(?:\[\d+\])?: )?"
)

#: HAProxy's `option httplog`:
#: `%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc
#: %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r`.
_HAPROXY: Final = (
    _HAPROXY_ENVELOPE
    # Split at the last colon. The port is always written, so this is right
    # for an IPv6 address written bare too; a UNIX socket reads as `unix`.
    + r"(?P<client_ip>\S+):(?P<client_port>\d+)"
    # `%tr`, local time with no zone: read as UTC, like every stamp without one.
    + r" \[(?P<timestamp>\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d\.\d{3})\]"
    + r" (?P<frontend>\S+) (?P<backend>[^\s/]+)/(?P<server>\S+)"
    # `option logasap` puts a `+` before the total time and the bytes.
    + r" (?P<timers>-?\d+/-?\d+/-?\d+/-?\d+/\+?-?\d+) (?P<status>-?\d+) \+?(?P<bytes_sent>\d+)"
    + r" (?P<captured_request_cookie>\S+) (?P<captured_response_cookie>\S+)"
    + r" (?P<termination_state>\S{4}) (?P<connections>\d+/\d+/\d+/\d+/\+?\d+)"
    + r" (?P<queues>\d+/\d+)"
    # Only there when headers are captured. Which captured header is which is
    # configuration, so none is read as the User-Agent. One block alone is
    # read as the request's, the common case.
    + r"(?: \{(?P<captured_request_headers>[^}]*)\})?"
    + r"(?: \{(?P<captured_response_headers>[^}]*)\})?"
    # The closing quote is optional: HAProxy cuts a line at 1024 bytes by
    # default, and a long query is where an attack usually is. `"` is `#22`
    # inside it, so `[^"]` cannot stop early. Anything after is ignored
    # (`option httpslog` adds TLS fields there).
    + r' "(?P<request_line>[^"]*)"?'
)


#: An Application Load Balancer's access log, its fields in AWS's order and
#: shaped as AWS's own Athena regex shapes them. Required through
#: `request_creation_time` (22), optional through `classification_reason` (29),
#: and nothing after it is read: AWS adds fields at the end and asks parsers to
#: stop after the last one they know.
_AWS_ALB: Final = (
    r"(?P<type>[a-z][a-z0-9]*) \d{4}-\d\d-\d\dT[\d:.]+Z (?P<elb>\S+)"
    # Split at the last colon: ALB always writes the port.
    + r" (?P<client_ip>\S+):(?P<client_port>\d+) (?P<target>\S+)"
    + r" (?P<request_processing_time>[-.0-9]+) (?P<target_processing_time>[-.0-9]+)"
    + r" (?P<response_processing_time>[-.0-9]+) (?P<status>-?\d*) (?P<target_status_code>\S+)"
    + r" (?P<bytes_in>\d+) (?P<bytes_sent>\d+)"
    # The target is a whole URL by construction, so it is read as one. A URI
    # may hold a raw space (ALB logs that as `SpaceInUri`). `host:port-` is
    # what ALB writes for a path it refused: no path, not `/`.
    + r' "(?P<method>[^ "]*)'
    + r" (?:(?P<url_path_not_logged>[A-Za-z][A-Za-z0-9+.-]*://[^/ ]*:\d+)-|(?P<url>.*?))"
    + r' (?P<protocol>- |[^ ]*)" "(?P<user_agent>[^"]*)"'
    + r" (?P<ssl_cipher>[A-Z0-9_-]+) (?P<ssl_protocol>[A-Za-z0-9.-]+) \S+"
    + r' "(?P<trace_id>[^"]*)" "(?P<domain_name>[^"]*)" "[^"]*" (?:-?\d+|-)'
    # `request_creation_time`: when the request arrived, the instant Apache's
    # `%t` means. The stamp at the front is when it was answered.
    + r" (?P<timestamp>\d{4}-\d\d-\d\dT[\d:.]+Z)"
    + r'(?: "(?P<actions_executed>[^"]*)" "[^"]*" "(?P<error_reason>[^"]*)"'
    + r'(?: "[^"]*" "[^"]*" "(?P<classification>[^"]*)" "(?P<classification_reason>[^"]*)")?)?'
)


#: What Envoy writes at the front of its default line and of Istio's: the start
#: time, always UTC, and the request line. Envoy writes a client's quotes as
#: they came, so the request line is read as exactly three words — HTTP/1 has no
#: room for a raw space in a path. Read any looser, a `"` in the path could end
#: the field early and hand what follows to whatever the client wrote next.
_ENVOY_HEAD: Final = (
    r'\[(?P<timestamp>\d{4}-\d\d-\d\dT[^\]]+)\] "(?P<request_line>\S+ \S+ \S+)"'
    r" (?P<status>\d{1,3}) (?P<response_flags>\S+)"
)

#: The three quoted fields after the User-Agent. Envoy refuses a Host with a
#: quote in it and writes the upstream itself; a client's X-Request-ID may
#: carry quotes, which only moves text between it and the User-Agent.
_ENVOY_TAIL: Final = (
    r'"(?P<req_header_x_request_id>[^"]*)" "(?P<host>[^"]*)" "(?P<upstream_host>[^"]*)"'
)

#: Istio's `EnvoyTextLogFormat`, the mesh's default text access log. The client
#: is `DOWNSTREAM_REMOTE_ADDRESS`, read from the end of the line, where nothing
#: a client sends can reach: the fields there are Envoy's own, and Envoy
#: sanitises the SNI (`invalid:5.6.7.8_1_z` for one with a space in it). So a
#: User-Agent carrying a fake set of addresses cannot move them. Without
#: `use_remote_address`, Envoy takes that address from X-Forwarded-For and
#: writes its port as 0, which is kept.
_ISTIO: Final = (
    _ENVOY_HEAD
    + r" (?P<response_code_details>\S+) (?P<connection_termination_details>\S+)"
    + r' "(?P<upstream_transport_failure_reason>[^"]*)"'
    + r" (?P<bytes_in>\d+) (?P<bytes_sent>\d+) (?P<duration_ms>\d+|-)"
    + r" (?P<upstream_service_time>\S+)"
    + r' "(?P<req_header_x_forwarded_for>[^"]*)" "(?P<user_agent>.*)" '
    + _ENVOY_TAIL
    + r' (?P<upstream_cluster>[^\s"]+) (?P<upstream_local_address>[^\s"]+)'
    + r' (?P<downstream_local_address>[^\s"]+) (?P<client_ip>[^\s"]+)'
    + r' (?P<requested_server_name>[^\s"]+) (?P<route_name>[^\s"]+)\s*$'
)


#: An address as an X-Forwarded-For entry writes it: IPv4 with or without a
#: port, IPv6 in brackets with or without one, or IPv6 bare (two colons at
#: least, which no hostname or word has).
_ADDRESS: Final = (
    r"(?:\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?"
    r"|\[[0-9A-Fa-f:.]+\](?::\d{1,5})?"
    r"|(?=[0-9A-Fa-f.]*:[0-9A-Fa-f.]*:)[0-9A-Fa-f:.]{2,45})"
)

#: An entry of a list that is an address and is followed by `" "`: the place a
#: field could end if the line were read that way.
_SPLIT: Final = rf'\s*{_ADDRESS}" "'

#: Envoy's default access log. It records no client address, so the client is
#: the last X-Forwarded-For entry: with `use_remote_address: true`, Envoy's
#: advice for an edge proxy, Envoy appended the address it saw; without it the
#: last entry is what Envoy itself takes as the client. With no entry at all
#: there is no client, and the line is refused.
#:
#: Envoy writes a client's quotes as they came, in X-Forwarded-For and in the
#: User-Agent alike, so a client can fake where one ends and the other begins.
#: The line is read only when exactly one reading leaves X-Forwarded-For
#: ending in an address after a comma or at its start: X-Forwarded-For takes
#: entries until the first that is an address followed by `" "`, and the
#: User-Agent may then hold no comma followed by one. A second such place means
#: a second possible client — the same bytes are written for either — and the
#: line is refused rather than pinned on an address its sender may have chosen.
_ENVOY: Final = (
    _ENVOY_HEAD
    + r" (?P<bytes_in>\d+) (?P<bytes_sent>\d+) (?P<duration_ms>\d+|-)"
    + r" (?P<upstream_service_time>\S+)"
    + rf' "(?P<req_header_x_forwarded_for>(?:(?!{_SPLIT})[^,]*,)*\s*(?P<client_ip>{_ADDRESS}))"'
    + rf' "(?P<user_agent>(?:[^,]|,(?!{_SPLIT}))*)" '
    + _ENVOY_TAIL
    + r"\s*$"
)


def _pattern(
    name: str, description: str, pattern: str, *, time_format: str = "", escapes: str = ""
) -> PatternFormatSpec:
    return PatternFormatSpec(
        name=name,
        pattern=pattern,
        time_format=time_format,
        description=description,
        escapes=escapes,
    )


#: Every format logarc ships with, most specific first. See the module
#: docstring for why the order is not cosmetic.
BUILT_INS: Final[tuple[FormatSpec, ...]] = (
    # -- Apache and the servers that copy its output ------------------------
    _apache(
        "apache-vhost-combined",
        VHOST_COMBINED,
        "Apache vhost_combined: combined with the server name and port in front",
    ),
    # ingress-nginx's `log-format-upstream`, the default it ships. Its nginx
    # variables in Apache's terms: `$request_length` is `%I`, `$request_time`
    # is `%T`, and what the controller sets is `%{...}e`. The upstream fields
    # turn into lists when a request is retried (`a, b`) or sent to an error
    # page (`a : b`), and `$req_id` is the client's own X-Request-ID when it
    # sends one — both are why the directive compiler reads lists, and reads a
    # field that ends the line to its end.
    _apache(
        "ingress-nginx",
        f"{COMBINED} %I %T [%{{proxy_upstream_name}}e] [%{{proxy_alternative_upstream_name}}e]"
        " %{upstream_addr}e %{upstream_response_length}e %{upstream_response_time}e"
        " %{upstream_status}e %{req_id}e",
        "Kubernetes ingress-nginx's default: combined with the upstream it reached",
    ),
    # Before `apache-combined-io`, and measured rather than guessed: io's two
    # trailing counts are bare fields, which match `"198.51.100.9" 0.123`
    # quotes and all, so an nginx line satisfies both and the earlier one wins.
    # The other way round is not ambiguous — io's `412 291` has no quotes for
    # nginx's forwarded-for field to match.
    _apache(
        "nginx-combined-forwarded",
        f'{COMBINED} "%{{X-Forwarded-For}}i" %T',
        "nginx combined with the forwarded-for header and $request_time",
    ),
    # What nginx.org's packages and the official Docker image log by default.
    # Before `apache-combined-io` for the reason above, on a line of its own:
    # behind two proxies the forwarded-for is `"a, b"`, and io's two counts
    # match its halves.
    _apache(
        "nginx-main",
        f'{COMBINED} "%{{X-Forwarded-For}}i"',
        "nginx's packaged default 'main': combined with the forwarded-for header",
    ),
    # Traefik's `common`, its text access log. It drops request headers unless
    # told to keep them, so by default the Referer and User-Agent are `-`.
    _apache(
        "traefik-common",
        f'{COMBINED} %{{request_count}}e "%{{router_name}}e" "%{{service_url}}e"'
        " %{duration_ms}ems",
        "Traefik's default text access log: combined with its router and service",
    ),
    _apache(
        "apache-combined-io",
        f"{COMBINED} %I %O",
        "Apache combined with mod_logio's byte counts on the end",
    ),
    _apache(
        "apache-combined",
        COMBINED,
        "Apache combined. nginx's built-in 'combined' is byte-identical to it",
    ),
    _apache(
        "apache-vhost-common",
        f"%v {COMMON}",
        "Apache common with the server name in front",
    ),
    _apache("apache-common", COMMON, "Apache common, the oldest and smallest"),
    # -- Proxies and load balancers with a line of their own ---------------
    # Each one writes the client with its port, and none of their lines
    # matches another's, so their order among themselves is cosmetic.
    _pattern(
        "haproxy",
        "HAProxy's option httplog, in any syslog envelope; its #XX escapes undone",
        _HAPROXY,
        time_format="%d/%b/%Y:%H:%M:%S.%f",
        escapes="haproxy",
    ),
    _pattern("aws-alb", "AWS Application Load Balancer access logs", _AWS_ALB),
    _pattern("istio", "Istio's Envoy access log, the mesh's default text format", _ISTIO),
    _pattern(
        "envoy",
        "Envoy's default access log; the client is the last X-Forwarded-For entry",
        _ENVOY,
    ),
    # -- JSON, one object per line -----------------------------------------
    _json(
        "nginx-json",
        "nginx's widely copied JSON escape template",
        timestamp="time_local",
        client_ip="remote_addr",
        request_line="request",
        status="status",
        bytes_sent="body_bytes_sent",
        referer="http_referer",
        user_agent="http_user_agent",
    ),
    # Caddy's `request.uri`, Traefik's `RequestPath` and Cloudflare's
    # `ClientRequestURI` hold the query too; a mapped path is split at its `?`
    # (`parsers.base.read_target`), so they map to `path` and read like `%r`.
    _json(
        "caddy-json",
        "Caddy's default JSON access log",
        timestamp="ts",
        client_ip="request.remote_ip",
        method="request.method",
        path="request.uri",
        protocol="request.proto",
        status="status",
        bytes_sent="size",
        host="request.host",
        referer="request.headers.Referer",
        user_agent="request.headers.User-Agent",
    ),
    _json(
        "traefik-json",
        "Traefik's JSON access log",
        timestamp="StartUTC",
        client_ip="ClientHost",
        method="RequestMethod",
        path="RequestPath",
        protocol="RequestProtocol",
        status="DownstreamStatus",
        bytes_sent="DownstreamContentSize",
        host="RequestHost",
        referer="request_Referer",
        user_agent="request_User-Agent",
    ),
    _json(
        "cloudflare-json",
        "Cloudflare Logpush HTTP requests",
        timestamp="EdgeStartTimestamp",
        client_ip="ClientIP",
        method="ClientRequestMethod",
        path="ClientRequestURI",
        protocol="ClientRequestProtocol",
        status="EdgeResponseStatus",
        bytes_sent="EdgeResponseBytes",
        host="ClientRequestHost",
        referer="ClientRequestReferer",
        user_agent="ClientRequestUserAgent",
    ),
    _json(
        "gcp-http-json",
        "Google Cloud load balancer request logs",
        timestamp="timestamp",
        client_ip="httpRequest.remoteIp",
        method="httpRequest.requestMethod",
        # A whole URL — "the scheme, the host name, the path and the query" —
        # read as host, path and query rather than as one long path.
        url="httpRequest.requestUrl",
        protocol="httpRequest.protocol",
        status="httpRequest.status",
        bytes_sent="httpRequest.responseSize",
        referer="httpRequest.referer",
        user_agent="httpRequest.userAgent",
    ),
    _json(
        "ecs-http",
        "Elastic Common Schema, as Filebeat and the agents write it",
        timestamp="@timestamp",
        client_ip="client.ip",
        method="http.request.method",
        path="url.path",
        query="url.query",
        status="http.response.status_code",
        bytes_sent="http.response.body.bytes",
        host="url.domain",
        # ECS spells it the RFC's way. `http.version` is not mapped: it holds
        # `1.1`, where every other format's protocol reads `HTTP/1.1`.
        referer="http.request.referrer",
        user_agent="user_agent.original",
    ),
    # -- Tables that name their own columns --------------------------------
    ColumnsFormatSpec(
        name="iis-w3c",
        description="IIS and anything else writing W3C extended, columns from #Fields:",
        fields=(
            ("timestamp", "date+time"),
            ("client_ip", "c-ip"),
            ("method", "cs-method"),
            ("path", "cs-uri-stem"),
            ("query", "cs-uri-query"),
            ("status", "sc-status"),
            ("bytes_sent", "sc-bytes"),
            ("host", "cs-host"),
            ("referer", "cs(Referer)"),
            ("user_agent", "cs(User-Agent)"),
        ),
    ),
    ColumnsFormatSpec(
        name="cloudfront",
        description="AWS CloudFront standard logs: W3C, tab separated",
        separator="\t",
        fields=(
            ("timestamp", "date+time"),
            ("client_ip", "c-ip"),
            ("method", "cs-method"),
            ("path", "cs-uri-stem"),
            ("query", "cs-uri-query"),
            ("status", "sc-status"),
            ("bytes_sent", "sc-bytes"),
            ("host", "cs(Host)"),
            ("referer", "cs(Referer)"),
            ("user_agent", "cs(User-Agent)"),
        ),
    ),
)
