# ADR-0001: Layered architecture around a canonical event schema

- **Status:** Accepted
- **Date:** 2026-08-08

## Context

`logarc` must support Apache access logs first, but is expected to support nginx, IIS W3C and
JSON logs later without a redesign. It must also ship as a Windows GUI while remaining usable and
testable headlessly.

Two forces pull in opposite directions:

1. Each log format has its own field set, ordering, and quoting rules.
2. Everything downstream of parsing — sessionization, classification, episode building, graph
   construction — is format-independent and should be written exactly once.

## Decision

Define a single **canonical event schema**, `core.event.NormalizedEvent`, and make it the only
type that crosses the parser boundary. Every parser is an adapter that produces it; nothing
downstream ever sees a format-specific representation.

Layer the codebase so dependencies point inward:

```
parsers → core ← detect ← episode ← graphbuild
             ↑
   ingest/storage        cli, gui  (outermost)
```

- `core/` holds domain models only. It imports no other layer and performs no I/O.
- `gui/` is the only module permitted to import PyQt. Anything the GUI can do must also be
  reachable from the CLI.

Adding a log format is one new `LogParser` implementation plus a registry entry — no changes
anywhere else.

## Consequences

**Positive.** Downstream logic is written once and tested once. Formats and storage backends are
swappable behind protocols. The engine is fully testable without a display.

**Negative.** Format-specific fields that do not map to the canonical schema must go into
`extra: Mapping[str, str]`, which is untyped. This is an accepted trade: the alternative is
either a union type that every consumer must destructure, or a schema that grows a column for
every format we ever meet.

**Constraint accepted.** The canonical schema is now a compatibility surface. Adding a required
field to it is a breaking change for all parsers, so new optional fields go into `extra` until
they prove general enough to promote.
