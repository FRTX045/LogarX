# What Zodiarc cannot tell you

Zodiarc reads access logs, and an access log is a record of requests and the
status codes that answered them. Everything below follows from that. These are
the limits to keep in mind when reading a reconstruction or quoting one; the
limits of the accuracy figures themselves are in
[evaluation.md](evaluation.md#limits-of-these-numbers).

## It sees only what the log holds

A typical access log records the request line, the status, the response size,
the user agent and the time. It does not record form or request bodies, so the
payload of an attack in an unlogged POST body is invisible, though the pattern of
requests and their status codes may still reveal it: repeated sign-in attempts
show as many `POST /login` lines and their status codes, never as the passwords
tried. It
does not record what happened inside the application either. A format that logs
more fields gives the rules more to match, and nothing a format leaves out can be
recovered.

## A status code is not an outcome

Each activity's outline summarises the status codes it received
(`derive_outcome` in `src/zodiarc/core/episode.py`). Requests with no status are
left out. With no known status the outcome is *unknown*; otherwise it is
*success* when every status is below 400, *blocked* when every one is 400 or
above, and *mixed* in between. So a redirect counts as success, and an activity
answered only with server errors counts as blocked. An injection attempt answered with HTTP 200
was answered, not necessarily exploited. The response sizes and the lines
themselves are what to read next; the label is where to start, not a verdict.
The window words the three as *served*, *partly served* and *refused*, and the
HTML report in the same terms, which say what was measured; the JSON export and
the command line keep the values above.

## A client is an IP address, not a person

Activity is grouped by the address the log recorded. People behind one shared
address, such as an office or a mobile carrier, become one client, and one person
moving between addresses becomes several. Behind a reverse proxy or a CDN the
logged address may be the proxy's own, which puts every visitor in one client. A
JSON format can map the client address to a forwarded field, and a pattern
format can capture it from wherever the line holds it; see
[log-formats.md](log-formats.md). The field must hold the intended client
address: mapping a comma-separated forwarding chain does not resolve it into one
trusted address.

## It answers from the logs it was given

"When it started" means the first request in the logs read into the case, and
"is it still going" means whatever the last of them shows. A log that was rotated
away, or a second server that was not included, is not in the answer.

## It works after the fact

Zodiarc reads logs that have already been written. It does not watch live
traffic, raise alerts or block anything.

## It runs as a desktop application

The window is the only way a user works with Zodiarc
([ADR-0012](adr/0012-the-window-is-the-product.md)). The packaged application
has no supported headless workflow, so it is not a batch job for a server. A
source checkout keeps `zodiarc-dev` as developer tooling, to build cases and
measure the project, and nothing a user needs is only there.

## The raw lines stay where they were

A case stores the parsed requests, but the evidence panel reads each raw line
from the original log file at the path recorded when it was read in. A case
copied to another machine keeps its stored requests, bookmarks and notes;
showing the raw lines needs the logs at those same paths. A log that has changed
size since it was read in is flagged rather than trusted, but an edit that keeps
the size is not caught by that check: opening evidence does not recompute the
SHA-256. Reopening a case also reconstructs it with the rules installed now,
which may differ from the ones it was first read with.

## Its accuracy is measured on one application

The headline accuracy figures come from one PHP shop with modelled timestamps
([evaluation.md](evaluation.md)). Nothing yet separates what is true of Zodiarc
from what is true of that shop, so the figures are evidence, not a guarantee for
every site.
