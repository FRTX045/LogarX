# Security policy

logarc reads access logs. Every byte it parses was written by whoever was talking
to the web server, which means an attacker chooses most of its input on purpose.
A defect here is not only a crash — it can be a way to reach the machine of the
person investigating the attack.

That is the threat this policy is about.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting**, on this repository's *Security*
tab: *Report a vulnerability*. It opens a private advisory that only the
maintainers can see.

Please do not open a public issue for something exploitable. An issue is
world-readable the moment it is filed, and the people running this tool are
usually reading logs from an incident that is still live.

Tell us what you can:

- what logarc does that it should not, and what you expected instead
- the smallest input that causes it — a log line, a format definition, a rule
- which version, and how it was installed (source, or the packaged Windows build)
- whether it needs anything unusual: a particular platform, the OWASP CRS
  sidecar, a custom format

A proof of concept is welcome. A working exploit is not required — a clear
description of the mechanism is enough to start.

## What we will do

This is a small project. There is no security team and no paid response, so the
honest commitment is modest and specific:

- **Acknowledged within a week.** If you have heard nothing after seven days,
  assume the report was missed and say so again.
- We will tell you plainly whether we think it is a vulnerability, and why.
  Sometimes the answer will be that it is a bug rather than a security issue,
  and we will say which and explain the reasoning.
- A fix, when there is one, ships with a note in `CHANGELOG.md` naming what was
  wrong. Credit goes to the reporter unless you ask us not to.
- If we cannot fix something, we will document it rather than leave it quiet.

We do not run a bug bounty and cannot pay for reports.

## In scope

Anything that lets a crafted log, format or rule harm the person running logarc:

- **Code execution** from a log line, a format definition, or a rule pack.
- **Denial of service** on ordinary input — a regular expression that takes
  minutes on one line, a decompression ratio nothing bounds, memory that grows
  without limit on a single crafted line.
- **Writing outside the case directory**, or reading a file the user did not
  point the tool at. Any input that becomes a filename is a candidate.
- **A case that looks complete and is not.** This one matters more here than in
  most tools: logarc's entire purpose is to be believed about what a log
  contains. Anything that makes evidence silently disappear — lines dropped
  without being quarantined and counted, an episode that omits requests it
  covers, an integrity record that fails to notice a changed source file — is a
  security defect in this project, not merely a bug. Report it as one.
- **Tampering with a case record** so that `case.json` no longer describes what
  actually happened.

## Out of scope

- **The attacks logarc detects.** SQL injection in a log line is the subject
  matter. A report that logarc "contains" attack patterns, or that its rule packs
  match on payloads, describes the tool working.
- **Vulnerabilities in OWASP CRS or Coraza.** Those belong upstream:
  [coreruleset](https://github.com/coreruleset/coreruleset),
  [coraza](https://github.com/corazawaf/coraza). We will help route a report if
  it is unclear which side a defect is on.
- **Anything that needs a modified logarc**, a debugger attached, or a rule pack
  the user did not choose to install.
- **A catastrophic regular expression in a format *you* wrote.** A custom format
  can carry any pattern, and logarc compiles and runs it. Some patterns take
  exponential time: `(?:\w+\s*)+` — a natural way to write "some words here" —
  was measured running for over 25 seconds on a single 81-character line, and it
  does not stop. Nothing checks a pattern's cost, and this is documented rather
  than fixed because every guard we measured either missed the textbook case or
  refused patterns that are fine, and a guard that misses is worse than none.

  It is narrower than it looks: saved formats are loaded from your own
  `~/.logarc/formats.json` at startup and **never from a case**, so opening
  someone else's case does not run their pattern. Treat a format definition from
  someone else the way you would treat their code.

- **The packaged Windows build being unsigned.** Known, and not a finding: the
  build carries no code-signing identity, so SmartScreen will warn on a
  downloaded copy. Build from source if that matters to you.

## Supported versions

Early development. The current release is **0.2.0**, and **only the current
`main` is supported** — fixes land there and are carried into the next tag rather
than backported. When that stops being a reasonable policy, this section will
name which releases still receive them.

## What logarc does not do

Stated here because it narrows the attack surface, and because someone assessing
the tool will want it in one place:

- It makes **no outbound network connections**. Runtime dependencies are pyarrow,
  duckdb, pyyaml, pydantic, typer and rich — no cloud SDK, no telemetry, no
  model. The optional CRS step runs a local binary against a local copy of the
  ruleset; it is not a service.
- It **opens source logs read-only** and records a SHA-256 of each at ingest.
- It needs **no account, no API key, and no elevated privileges**.
