# ADR-0010: A log format is data, and it travels with the work

- **Status:** Accepted
- **Date:** 2026-08-28

## Context

logarc shipped three formats — `apache-vhost-combined`, `apache-combined`,
`apache-common` — all of them a `LogFormatParser` built from a directive
string. The machinery for a fourth had been in `parsers/registry.py` from the
start: `register_logformat(name, directive)`.

Nothing could reach it.

- `MainWindow._ingest_new_case` passed no `log_format` at all. Every ingest
  from the window was auto-detected, and there was no control anywhere that
  offered a choice.
- The CLI's `--format` took a *name*, and the only names were the three
  built-ins. `logarc formats` told the reader that "a custom Apache or nginx
  format is supported by passing its directive string" — which nothing
  accepted.
- `register_logformat` was reachable only from a Python script importing
  logarc, and a format registered that way died with the process.

So the extension point existed and was unreachable, and a site running its own
`LogFormat` could not use the tool at all.

Three constraints decide the shape of the fix, and none of them is negotiable.

**The engine is Qt-free** ([ADR-0001](0001-layered-architecture-and-canonical-event-schema.md)).
`src/logarc/` outside `gui/` imports no PyQt6, so a saved-format store cannot
live in `QSettings`.

**Ingest workers are started by spawn**
([ADR-0009](0009-parallel-ingest-rather-than-a-native-parser.md)). A worker
re-imports `parsers.registry` and gets the three presets and nothing else. A
format registered in the parent is simply absent in the child.

**A case must stay readable for as long as it is kept.** `case.json` recorded
`log_format` as a name, and `evidence._parser_for` returned `None` when that
name no longer resolved. Its docstring already anticipated the day a case
outlived the thing that read it. Letting users edit and delete formats is that
day.

## Decision

**Stop passing the format's name. Pass the definition itself.**

A format is a record — `parsers/spec.py`, a frozen slots dataclass that is
picklable, Qt-free and convertible to JSON — and the parser is built from the
record rather than the other way round.

The records are a tagged union keyed on `kind`. `LogFormatSpec` holds an Apache
directive; `JsonFormatSpec` holds a mapping from our field names to a JSON log's
keys, which is the shape that proved the union was worth having — it matches by
name where the first matches by position, so nothing in the machinery around
them could have been leaning on a format being a directive string. Each kind
renders its own JSON payload rather than having one derived from its dataclass,
because the library file is meant to be openable in an editor: a mapping held as
pairs in memory is still written as an object.

`ColumnsFormatSpec`, the third, is the one that stretched the design: **part of
its definition lives in the log.** A W3C file declares its columns in a
`#Fields:` line. So a spec gained `resolved(sample)`, called in the process that
opened the file, returning the definition that will actually be used — and it is
*that* one which travels to a worker and into the case. The other two kinds
answer `self`. Two consequences worth stating: a worker handed a byte range has
never seen the header, so resolving in the parent is not an optimisation but the
only correct place; and a case has to record the columns it read, or reading it
back depends on a file nobody kept.

It also split "is this definition well formed" from "build a parser out of it".
The library validates a saved format by building one, which a table format
cannot do until a file is in hand — so each kind now answers `check()` for as
much of itself as can be judged with no file at all.

One change, and each of the three constraints stops being a problem:

| | before | after |
|---|---|---|
| worker | given a name it must resolve, and cannot | given the definition; resolves nothing |
| case | stores a name | stores the definition, in `SourceRecord.format_spec` |
| reuse | nothing to store | the definition is data, so a file holds it |

**The saved-format library is a plain JSON file the user owns**, located by
hand under the platform config directory with `LOGARC_HOME` overriding it.
**Only the GUI and the CLI ever read it.** The engine works from what it was
handed and from what the case recorded, so an emptied, damaged or absent
library costs the reader their saved definitions and no case.

**Loading a definition is not compiling it.** `spec_from_dict` accepts a
definition that will not build; `build()` is where that fails. A stored
definition that could refuse to *load* would take a whole case down over one
broken format, where today the line text stays readable and only its fields go
missing.

**A case whose format has since been edited reads in full, and says so.** The
definition it stored is the one it reads with. The window puts up a strip
naming both definitions — reassurance first, difference second, because a strip
above a case otherwise reads as "your case is wrong" and this one means the
opposite. Nothing is said when the format was merely *deleted*: the case reads
correctly from its own copy, and warning there would only teach the reader to
dismiss warnings.

## Consequences

**A format written once is a first-class one.** Saved by name, offered wherever
the built-ins are, usable in every later case, and taking part in
auto-detection — a log in a saved format is now detected without `--format` at
all.

**Built-ins cannot be shadowed.** Registration order is preference order, so a
saved format taking the name `apache-combined` would never be reached, and a
case recording that name would quietly begin to mean something else.
`register_saved_formats` skips such a name and both interfaces refuse it.

**The registry became stateful in a way it was not.** `register_saved_formats`
reconciles — it removes what a previous call installed before adding — because
a long-lived window that only ever added would go on offering a format the
reader had deleted. `is_built_in` exists for the same reason: every caller was
otherwise working the answer out by subtracting the library file from
`available_formats()`, which is right only while those two agree.

**`_Task` grew a field that is not a string.** Its docstring used to promise
"only paths, a chunk and strings". The promise it was making — everything here
survives pickling to a spawned process — is kept; the wording is not.

**Two kinds of registration now differ in what they can do.**
`register_spec` takes data and reaches workers and cases. `register_format`
takes a factory, which is code and reaches neither. `get_spec` returns `None`
for the second so callers fall back rather than silently carry nothing. That is
the plugin case `evidence._parser_for` was always written for.

## What this is not

**Not a guess at what a log line means.** The editor shows a rule and what that
rule read, side by side. Pointing at parts of a pasted line and naming them was
considered and rejected: a guess that is nearly right is worse than none here,
because the reader accepts it and finds out at ingest.

**Not nginx `log_format` support.** Measured, 2026-08-28: an nginx `log_format`
definition is rejected outright — `no directives found`. What is true is that
nginx's default *output* is byte-identical to Apache's `combined` and is read
by `apache-combined` at confidence 1.0. The docstrings claiming otherwise were
corrected as part of this work.
