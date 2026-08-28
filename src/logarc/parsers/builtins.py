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

Not included, deliberately: the formats that write the client as `address:port`
— AWS ALB, Envoy, HAProxy. Stripping the port is not safe without deciding what
to do about IPv6, where the colons are part of the address, and a wrong answer
turns every connection from one client into a client of its own. Those logs are
still readable with a pattern of the reader's own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from logarc.parsers.apache import COMBINED, COMMON, VHOST_COMBINED
from logarc.parsers.spec import ColumnsFormatSpec, JsonFormatSpec, LogFormatSpec

if TYPE_CHECKING:
    from logarc.parsers.spec import FormatSpec

__all__ = ["BUILT_INS"]


def _apache(name: str, directive: str, description: str) -> LogFormatSpec:
    return LogFormatSpec(name=name, directive=directive, description=description)


def _json(name: str, description: str, **fields: str) -> JsonFormatSpec:
    return JsonFormatSpec(name=name, fields=tuple(fields.items()), description=description)


#: Every format logarc ships with, most specific first. See the module
#: docstring for why the order is not cosmetic.
BUILT_INS: Final[tuple[FormatSpec, ...]] = (
    # -- Apache and the servers that copy its output ------------------------
    _apache(
        "apache-vhost-combined",
        VHOST_COMBINED,
        "Apache vhost_combined: combined with the server name and port in front",
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
    _apache(
        "apache-combined-io",
        f"{COMBINED} %I %O",
        "Apache combined with mod_logio's byte counts on the end",
    ),
    _apache(
        "apache-combined",
        COMBINED,
        "Apache combined. nginx's default output is byte-identical to it",
    ),
    _apache(
        "apache-vhost-common",
        f"%v {COMMON}",
        "Apache common with the server name in front",
    ),
    _apache("apache-common", COMMON, "Apache common, the oldest and smallest"),
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
        user_agent="request_User-Agent",
    ),
    _json(
        "cloudflare-json",
        "Cloudflare Logpush HTTP requests",
        timestamp="EdgeStartTimestamp",
        client_ip="ClientIP",
        method="ClientRequestMethod",
        path="ClientRequestURI",
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
        path="httpRequest.requestUrl",
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
