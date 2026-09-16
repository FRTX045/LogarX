# The demo log

`demo.log` is the file to open when you want to show somebody what logarc does.
It is 788 lines of three days' traffic against a fictional shop, and every
feature the application has is reachable from it.

```bash
logarc ingest samples/demo/demo.log --format apache-vhost-combined --case demo-case
logarc-gui                      # Case -> Open, pick demo-case
```

Or from the command line:

```bash
logarc list-ips --case demo-case
logarc analyze  --ip 192.0.2.111 --case demo-case
logarc evidence --ip 192.0.2.110 --case demo-case
logarc enrich   --case demo-case          # adds OWASP CRS; see "CRS" below
```

## What it covers, measured

These are figures from a run, not intentions:

| | |
|---|---|
| Lines / events / quarantined | 788 / 782 / 5 |
| Clients | 33 |
| Detection rules exercised | **71 of 71** |
| Attackers flagged | 21 of 21 |
| False alarms on the 12 ordinary clients | **0** without CRS, 1 with it |

Re-measure at any time:

```bash
python samples/demo/make_demo.py          # rebuilds; prints line count and sha256
```

The build is deterministic — no randomness anywhere — so the same script always
produces the same bytes. The current file is
`8b7ce4e3cab81a4a2caab7792dfe9d6651dca0755395c6beb6290e130cf0d40a`.

## The format, and why it is that one

`apache-vhost-combined`, not the more common `apache-combined`. The difference
is one field: vhost-combined records the `Host` header and plain combined does
not. Two things need it — `referer_offsite`, which compares the Referer's host
with the request's, and the `session_fixation` rule built on top of that. In
plain combined they are quietly unreachable, which is the wrong property for a
file whose entire job is to show what works.

One client also has `%u` populated (the authenticated username). logarc parses
that field and currently throws it away; having a line that carries one makes
the gap visible rather than theoretical.

## The cast

**Ordinary traffic — about two thirds of the file.** A log that is mostly
attacks is not a log, and it makes the detection look easier than it is.

| Client | What it is there to show |
|---|---|
| `198.51.100.10` | The full purchase journey: browse, search, cart, sign in, checkout, pay, sign out. Three visits over three days. This is the client the `action/` rule packs were written for |
| `198.51.100.11` | The same shape, abandoned at the basket |
| `198.51.100.12` | Signs in, resets a password, reads old orders, tracks a parcel — no browsing at all |
| `198.51.100.13` | Searches five times, buys nothing. **Also the CRS false positive — see below** |
| `198.51.100.14` | Almost pure API traffic, which is what a phone app looks like from the server |
| `198.51.100.15`–`.17` | Extra shoppers, so the ordinary clients are not all one shape |
| `198.51.100.20` | A signed-in administrator. Legitimate `/admin` access answered 200, and the only client whose lines carry a username. Kept clean on purpose: it is the counter-example |
| `203.0.113.50` | A `python-requests` price checker doing nothing wrong. **A regression test you can see** — this User-Agent used to be filed under reconnaissance, which made every harmless script an attacker |
| `66.249.66.1`, `40.77.167.1` | Googlebot and bingbot working through the catalogue, `robots.txt` first |

**Attacks — one client per thing worth showing**, so that clicking a name and
reading its story is a complete demonstration on its own.

| Client | What it is there to show |
|---|---|
| `192.0.2.100` | sqlmap: tautology, UNION, time-based, error-based, schema probe, stacked query. Payloads are percent-encoded, one of them twice, so the evidence panel has something to decode |
| `192.0.2.101` | Directory enumeration — 25 misses in 50 seconds. **The window rule no single line reveals** |
| `192.0.2.102` | The same idea paced to slip under it: 9 misses over 4 minutes |
| `192.0.2.103` | 12 refused sign-ins to one path |
| `192.0.2.104` | Path traversal, the same file asked for five ways — plain, encoded, double-encoded, null-byte, backslash. Normalisation collapses all five before any rule sees them |
| `192.0.2.105` | PHP: open tag, stream wrapper, superglobal, decode chain, comment evasion, config directive, `phpinfo()`, file function, object injection |
| `192.0.2.106` | XSS — script tag, event handler, `javascript:`, SVG. Sent with a **browser** User-Agent, deliberately (see below) |
| `192.0.2.107` | Command injection, Unix then Windows batch |
| `192.0.2.108` | SSRF: cloud metadata, loopback, `file://`, `gopher://` |
| `192.0.2.109` | Project metadata probe — is the repository the document root? |
| `192.0.2.110` | Session fixation: a session id in the URL arriving from somebody else's site. Last line is the control, same URL from our own page, which must not fire |
| `192.0.2.111` | Webshell: upload, then use. The 200 on the second request is what makes it serious — the file was served |
| `192.0.2.112` | Registration flood |
| `192.0.2.113` | Four scanners that do not hide, one request each |
| `192.0.2.114` | **30 round trips between two activities.** Open this one in both views: the trace draws 60 circles and tells you almost nothing, the behaviour map draws 2 with `x30` on the arrow between them. The clearest argument for why that second view exists |
| `192.0.2.115` | **Three visits, the middle one cut into seven activities.** The client to open when explaining the three levels — seven is past the point where a session folds onto a second row |
| `192.0.2.116` | Forced browsing: 12 refusals across 10 paths, then two redirects |
| `192.0.2.117` | Six requests that make the application fall over |
| `192.0.2.118` | Java stack: Log4Shell in the URL, the User-Agent and the Referer; an XML external entity; template injection |
| `192.0.2.119` | NoSQL operators smuggled into a parameter, then Shellshock — which is not in the URL at all, it is in the User-Agent |
| `192.0.2.120` | Sends no User-Agent. Graded as information, not as an attack |

**Six damaged lines** sit at the end. Five reach quarantine and one blank line
is skipped outright, so the ingest summary reads 5. They are there so a reader
meets the amber "could not be parsed" strip once on a log that does not matter,
before meeting it on one that does.

## Two things that look like bugs and are not

**`198.51.100.13` searches for "wall bracket", and CRS calls it a command
injection.** Rule 932236, critical severity, three times — because `wall` is a
real Unix command and CRS is matching a command name followed by an argument.
Nothing is wrong with CRS; it is doing what a generic ruleset must do without
knowing this site sells brackets. But it means a hardware shop's customers get
filed as attackers by the most widely deployed WAF ruleset in the world, and
that is worth seeing once with your own eyes. It is the demonstration behind
ADR-0008: CRS is enrichment somebody switches on, not a verdict the tool
reaches by itself.

So the table above carries two false-alarm figures and both are true. Without
CRS, zero. With CRS, this one. **Do not change those search terms.**

**The XSS client uses a browser User-Agent, not a scanner's.** The first draft
used Nikto's, and the episode came back named `Security Scanner User-Agent` —
critical beats the XSS rules' medium, so the client written to demonstrate XSS
demonstrated something else. A browser is also the truthful case: XSS is aimed
at a person's browser and usually arrives from one.

## Why no truth file

Every other corpus here ships a `.truth.jsonl` and `logarc evaluate` scores
against it. This one does not, and should not.

Scoring the rules against traffic written to suit them is marking your own
homework. The number it produces would be near-perfect, mean nothing, and be
quoted anyway. Evaluation belongs to the real labelled log under
`tests/data/apache-shopfront/` and to the OWASP CRS corpus, neither of which
this project wrote. See ADR-0005, ADR-0007 and ADR-0011.

This log answers "what can the tool show me". It must never be used to answer
"how good is the tool".

## Keeping it current

**This file is permanent, and that is a commitment to maintain it.** When a
feature lands that the demo log cannot show, add a client to
`make_demo.py` — a block with a comment saying what it is for — then re-run the
script and commit both the script and the log.

The check that matters is rule coverage, and the script does it for you. It is
71 of 71 today; a rule added to a pack that nothing in this log triggers makes
it fail and names the rule:

```bash
python samples/demo/make_demo.py            # rebuild
python samples/demo/make_demo.py --check    # exits non-zero if a rule is unreachable
```
