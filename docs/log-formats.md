# Log formats

In the window, **Case → Formats and rules…** shows the whole library, and a format
written there is tried against your log as you type.

![The format library: twenty-one built in, one written by the reader](images/screenshot-log-formats.png)

The format is detected from the first lines of a log. When it cannot be, ingest
**refuses rather than guessing** — the wrong parser quarantines every line and
presents as an empty result, which is the worst failure this tool has.

## What is read without naming a format

| Format | What writes it |
|---|---|
| `apache-combined` | Apache's `combined`, and the servers that write the same line: the nginx that Debian and Ubuntu package, OpenLiteSpeed, Express's morgan `combined`, Traefik's `genericCLF` |
| `apache-combined-io` | Apache `combined` with mod_logio's byte counts on the end |
| `apache-common` | Apache `common` |
| `apache-vhost-combined` | Apache `vhost_combined`: the server name and port in front |
| `apache-vhost-common` | Apache `common` with the server name in front |
| `nginx-main` | nginx from nginx.org's own packages and the official Docker image: `combined` plus the forwarded-for header |
| `nginx-combined-forwarded` | nginx `combined` plus the forwarded-for header and `$request_time` |
| `ingress-nginx` | Kubernetes ingress-nginx, its default `upstreaminfo` |
| `traefik-common` | Traefik's default text access log |
| `traefik-json` | Traefik with `format: json` |
| `haproxy` | HAProxy's `option httplog`, bare or in any syslog envelope |
| `envoy` | Envoy's default access log |
| `istio` | Istio's Envoy access log, the mesh's default text format |
| `nginx-json` | The JSON escape template nginx sites copy |
| `caddy-json` | Caddy's default access log |
| `cloudflare-json` | Cloudflare Logpush, HTTP requests |
| `gcp-http-json` | Google Cloud load balancer request logs |
| `ecs-http` | Elastic Common Schema, as Filebeat and the Elastic agents write it |
| `iis-w3c` | IIS, and anything else writing W3C extended |
| `aws-alb` | AWS Application Load Balancer access logs |
| `cloudfront` | AWS CloudFront standard logs |

Each one is tested against a line in the shape its server writes. For
`nginx-main`, `ingress-nginx`, `traefik-common`, `haproxy`, `envoy` and `istio`,
those lines were captured from the servers themselves. ingress-nginx's came from
nginx running its exact log format, and Istio's from Envoy running Istio's.
`aws-alb` is tested on AWS's own documented entries.

Four things are worth knowing about logs from containers and proxies:

- **Traefik keeps no request headers by default.** Its log writes `-` for the
  Referer and the User-Agent even when the request sent both, so the rules that
  read the User-Agent have nothing to read. Start Traefik with
  `--accesslog.fields.headers.names.User-Agent=keep` and
  `--accesslog.fields.headers.names.Referer=keep` to record them.
- **`docker logs` and `kubectl logs` mix in the server's own messages.** Start-up
  and error lines are not requests. They are set aside and counted, and never
  read as one. Detection needs 60% of the first 200 lines to be requests, so a
  log that is mostly messages is not recognised on its own. Measured: 200
  requests to the nginx image, half of them 404s, came to 59% once its error
  log was merged in. Choose `nginx-main` then, when opening the log asks
  which format it is in, rather than leaving it to detection.
  `docker logs nginx > access.log` keeps only the start-up lines and the
  requests, and is recognised.
- **Behind a load balancer, the client may be the load balancer.** These formats
  take the client from `$remote_addr`. ingress-nginx sets that to the real
  client only when it is told to trust what is in front of it
  (`use-forwarded-headers`, `enable-real-ip` or the PROXY protocol). A forwarded-for header is
  kept beside the event and never used as the client: anyone can write one.
- **Apache combined with `%D` on the end is no server's default.** It is a site's
  own setting, so it is a format to add once, in **Case → Formats and rules**:
  `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D`.

### Proxies that write the client with its port

HAProxy, ALB, Envoy and Istio write the client as `address:port`. The port is
taken off only where the format always writes one, so a bare IPv6 address is
never cut, and it is kept beside the event.

- **HAProxy** is read bare, as `log stdout format raw` writes it, or behind any
  syslog envelope it writes, or as rsyslog files it. It writes a `"` the client
  sent as `#22`, and Zodiarc turns that back into `"` before any rule reads it.
  Three things to know:
  - Its time has no zone, so it is read as UTC. That is right in a container.
    On a host that runs local time, every event is off by the zone.
  - It cuts a line at 1024 bytes by default, closing quote and all. Such a line
    is read as far as it goes.
  - Captured headers (`capture request header`) are kept, but none is read as
    the User-Agent: which header is which is configuration, not log.
- **AWS ALB** logs can be ingested as the `.log.gz` files S3 holds. The time is
  when the request arrived (`request_creation_time`), not when it was answered.
  A request whose path ALB did not log (`https://shop.example.com:443-`) has no
  path, rather than `/`.
- **Envoy**'s default log has no client address. The client is taken from the
  last X-Forwarded-For entry, which is what Envoy itself treats as the client:
  - With `use_remote_address: true`, Envoy's advice for an edge proxy, Envoy
    adds the address it saw, so the last entry is the real one.
  - Without it, the last entry is whatever arrived: right behind a load balancer
    that sets the header, the client's own choice if Envoy faces the internet.
  - A line with no X-Forwarded-For has no client. It is set aside and counted,
    and so is a request Envoy refused before routing. A log made mostly of such
    lines is not recognised: name the format, or better, add
    `%DOWNSTREAM_REMOTE_ADDRESS%` to Envoy's format, or use Istio's.

  Envoy also writes a client's quotes as they came. A client can use them to
  fake where X-Forwarded-For ends, and two different requests can then write
  the same line. Such a line is set aside and counted, not pinned on an address
  the sender may have chosen.
- **Istio**'s client is `DOWNSTREAM_REMOTE_ADDRESS`. Without
  `use_remote_address`, Envoy takes it from X-Forwarded-For and writes the port
  as `0`: a port of 0 marks a client that came from that header.

Every format, built in and saved, is listed in **Case → Formats and rules**,
with what each one reads.

A format you write yourself is a first-class one: saved by name, offered wherever
the built-ins are, usable in every later case. There are four kinds, all under
**New** in that dialog, and none of them needs Python. Paste a line of the log and
the preview shows what every field reads as before anything is saved.

- **Text (LogFormat)**: write the Apache `LogFormat` directive down, such as
  `%h|%t|"%r"|%>s|%b`, or paste nginx's `log_format` as it is in `nginx.conf`.
- **JSON**: one object per line. **Guess fields** proposes the mapping, nested
  keys included; change a row it got wrong, such as `client_ip` to
  `http_x_real_ip` behind a proxy.
- **Table (CSV, TSV, W3C)**: IIS declares its columns in `#Fields:`, most CSVs in
  the first row. **Guess fields** reads them.
- **Pattern (regular expression)**: anything else, syslog-wrapped or an
  appliance with a syntax of its own. The named groups are the mapping, and
  **Time format** takes a strftime pattern for a time that is neither ISO nor
  a number.

In a directive, a field in quotes or in brackets reads up to the closing quote
or bracket, spaces included, and may be empty. An unquoted header or variable
(`%{X-Forwarded-For}i`, `%{upstream_addr}e`) may be a list, `a, b` or `a : b`.
If it ends the line, it reads to the end of it. None of this narrows a field:
a line the plain reading accepts is read exactly as before.

In a JSON, table or pattern format, a field mapped to `path` that also holds the
query (`/search?q=oak`) is split at the `?`, the way a request line is. A field
mapped to `url` is a whole URL, such as Google's `requestUrl`, and is read as its
host, path and query. A client written with a port it cannot be confused with,
`203.0.113.5:51234` or `[2001:db8::1]:443`, is read as the address alone, and the
port is kept beside the event. A bare IPv6 address is left as written, since
`2001:db8::1:443` could end in a port or in its own last group.

A pattern for a log that escapes what it writes the way HAProxy does, `#22`
for `"`, takes `--escapes haproxy`, and the escapes are undone before anything
reads a field. `cloudfront` does the same for CloudFront's percent-encoding, and
does it once: CloudFront encodes `%` too, so a client's own `%2F` arrives as
`%252F`, and undone once it reads `%2F` again, which is what the client sent.
Undone twice it would read `/`, and the rules that look for encoding a client
used to slip past a filter would be looking at something else.

An nginx `log_format` can be pasted wherever a directive can: the whole
statement from `nginx.conf` (`log_format main '...' '...';`, comments and line
breaks included), its quoted strings, or the format alone. It is kept as you
wrote it and read as the directive it means. The common variables have one:
`$remote_addr` is the client, `[$time_local]` and `$time_iso8601` the time,
`$request` the request, `$http_user_agent` and every other `$http_…` a header,
`$request_uri` the path and the query. Any other variable, such as
`$upstream_response_time`, is kept beside the event. Three formats are refused,
each saying why:

- One that writes JSON (`escape=json`): read its log as a JSON format instead,
  with **New → JSON**, which proposes the mapping from a line of the log.
- One with no `$time_local` or `$time_iso8601`. `$msec` is not read yet.
- One with no `$remote_addr`. A forwarded-for header is the client's own to write,
  and is not read as the client.

A time format naming no year is **refused** rather than accepted: `strptime`
supplies 1900 for a missing year, and a case where every event is dated 1900 is
exactly the kind of number this tool exists not to emit.

**A format is a definition, not a name.** Each case records the definition it was
ingested with, so editing or deleting a saved format later cannot make an
existing case unreadable. See
[ADR-0010](adr/0010-a-log-format-is-data-that-travels-with-the-work.md).
