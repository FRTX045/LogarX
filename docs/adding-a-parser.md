# Adding a log format

Everything past ingest works from `NormalizedEvent`, so a new format needs to
produce one and nothing else has to change — not the segmenter, not the rules,
not the graph, not the window. That is the whole point of the canonical schema
(see [ADR-0001](adr/0001-layered-architecture-and-canonical-event-schema.md)).

There are two levels of effort, and most formats need the first.

## Level 1 — it is Apache-shaped

Apache's `LogFormat` directives are not hardcoded here; they are compiled. So a
site with its own directive string needs no code at all — write it down once
and it is yours from then on:

```bash
# See what the directive actually pulls out, before saving anything.
logarc formats check '%h %l %u %t "%r" %>s %b "%{X-Forwarded-For}i"' --log access.log

logarc formats add site-main '%h %l %u %t "%r" %>s %b "%{X-Forwarded-For}i"'
logarc ingest access.log --case ./case-001 --format site-main
```

`logarc formats check` is worth the extra step. A wrong directive does not
announce itself: it quarantines every line and presents as an empty case.

Saved formats live in a plain JSON file — `logarc formats` prints its path — and
are available to `--format`, to auto-detection, and to the window. Each case
also records the definition it was ingested with, so editing or removing a
saved format later cannot make an existing case unreadable.

From inside Python the same thing is `register_spec`:

```python
from logarc.parsers.registry import register_spec
from logarc.parsers.spec import LogFormatSpec

register_spec(LogFormatSpec(name="site-main", directive='%h %t "%r" %>s %b'))
```

Prefer that over `register_format`, which takes a factory. A factory is code:
it cannot be pickled to an ingest worker or written into a case, so a format
registered that way works only in the process that registered it.

A note on nginx. Its default `combined` output is byte-identical to Apache's,
so an ordinary nginx access log is already read by `apache-combined` with no
work at all. Its `log_format` *definition* syntax is a different matter: it uses
`$remote_addr` where Apache uses `%h`, and pasting one here is rejected with
`no directives found`. A custom nginx format has to be rewritten as the
equivalent Apache directive — `$remote_addr` becomes `%h`, `$request` becomes
`%r`, and so on.

## Level 2 — it is a different shape entirely

IIS W3C, a JSON log, an appliance with its own idea of a timestamp. Implement
the protocol in `logarc/parsers/base.py`:

```python
class LogParser(Protocol):
    name: str

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None: ...
```

Three things the contract asks of you, each for a reason:

**Return `None` for a line that is not in your format.** Do not raise. The
caller quarantines it and carries on, so one corrupt line does not end a
twelve-hour ingest. `None` is also how auto-detection scores candidates — a
parser that raises instead cannot be detected against.

**Return the event anyway when individual fields are unusable.** A line in your
format with a timestamp you cannot read should come back with the fields you did
get. Partial evidence is still evidence, and dropping the line loses the request
entirely.

**Be safe to share after construction.** Ingest builds one parser and hands it
to every worker. Keep per-line state in locals, not on `self`.

Then register it:

```python
from logarc.parsers.registry import register_format

register_format("iis-w3c", IisParser, description="IIS W3C extended log")
```

A factory rather than an instance: detection builds one parser per candidate
format while ingest shares one across workers, and the registry should not have
to know which is happening.

Registering over an existing name is refused rather than allowed to win.
Shadowing a built-in would silently change what an already-ingested case means.

## Filling in NormalizedEvent

```python
NormalizedEvent(
    timestamp=...,       # tz-aware, normalised to UTC
    client_ip=...,
    method=..., path=..., query=..., protocol=...,
    status=..., bytes_sent=...,
    referer=..., user_agent=..., host=...,
    evidence=ref,        # pass through untouched
)
```

`path` is the **raw** path — do not decode it. Normalisation happens later, in
`logarc.normalize.decode`, and both the raw and decoded forms are exposed to
rules as separate match fields. A parser that helpfully percent-decodes destroys
the distinction, and `decode_depth` — double-encoding, which is itself a signal
— becomes unobservable.

`evidence` is passed through as given. It is the reference that lets a node in
the finished graph point back at a line in the original file, and a parser is
the only place it can be attached.

Anything your format carries that these fields have no room for goes in `extra`.

## Test it

`tests/parsers/` is the place. Cover at minimum:

- a well-formed line producing the right event, **including the timezone** —
  timestamp handling is where log parsers go wrong most often, and a silent
  offset error moves every finding in the case
- a line from another format returning `None`
- a line in your format with a damaged field still returning an event
- the format winning auto-detection on a sample of its own lines, and losing on
  a sample of someone else's

The `logformat` compiler additionally has `hypothesis` property tests asserting
that any directive plus any field values round-trips. If you write a compiler
rather than a parser, do the same.

## What this does not cover

`logarc formats` and `--format` read the registry at the moment they run, so a
registration has to have happened first. There is currently no plugin discovery
— no entry-point scanning, no rule-pack-style directory of parsers — so
registering means importing a module that calls `register_format`, either in
your own script or by adding it to `logarc.parsers`. That is enough for a fork
or an embedded use, and it is not enough for distributing a parser as a separate
package. Entry-point discovery is the obvious next step and is not built.
