# ADR-0012: The window is the product; the command line is a developer tool

- **Status:** Proposed
- **Date:** 2026-10-17

## Context

logarc has had two ways in: the window (`logarc-gui`, and the packaged
`logarc.exe`) and a command line (`logarc`) with twelve commands and a
`formats` group of ten more. They grew side by side, so most features were
built, tested and documented twice.

The two are not used by the same people. The Windows application, which is
how anyone outside this project gets logarc, has never contained the command
line: it is built from `packaging/logarc_gui.py`, and its archive holds 1,155
Python modules, none of them from `logarc.cli` and none from `typer` or
`click` (read from the `PYZ` of the 2026-10-16 build). The command line exists
only in a source checkout.

What the command line does, by audience:

| | Commands | In the window? |
|---|---|---|
| Reading a case | `list-ips`, `analyze`, `evidence`, `export`, `site-hosts`, `formats …` | Yes: the client list, the reconstruction, the evidence panel, Export, the site-host prompt, Case → Log formats |
| Building a case | `ingest`, `enrich` | Yes: opening a log, Case → Run OWASP CRS on this case |
| Measuring the project | `evaluate`, `score-crs`, `benchmark`, `convert-csic` | No |
| Setting up a source checkout | `setup-crs` | No |

The last two groups are how this project checks itself. Every accuracy figure
in the README and `docs/evaluation.md` comes from `evaluate`, every rule-pack
pass reports `score-crs`, ingest speed and memory come from `benchmark`, and a
source checkout gets CRS from `setup-crs`. Removing those would stop the
project measuring what it changes, which is the one thing it is careful about.

## Decision

**The window is the only way a user uses logarc.** Nothing a user needs is
reachable only from a terminal, and the README describes the application, not
commands.

**The command line stays, as developer tooling, and is renamed to say so.**

- The package moves from `src/logarc/cli/` to `src/logarc/devtools/`, so the
  tree itself shows what ships (`gui/`) and what does not (`devtools/`).
- The command is `logarc-dev`, not `logarc`. A developer types it; a user is
  never told to.
- It keeps the commands the project needs to build cases and measure itself:
  `ingest`, `enrich`, `evaluate`, `score-crs`, `benchmark`, `convert-csic` and
  `setup-crs`. `ingest` and `enrich` stay because measuring starts from a case:
  an evaluation ingests a log, enriches it when the figure is for CRS, and
  then runs `evaluate`.
- The commands that only repeat the window are deleted: `list-ips`, `analyze`,
  `evidence`, `export`, `site-hosts` and the `formats` group. The engine they
  called stays; the window and its tests use it.

**The packaged application is checked to contain none of it.** The rebuild's
verification reads the module list out of the built application and fails if
any `logarc.devtools` module, `typer` or `click` is in it, the same way it
already refuses a build without its rule packs. Today that holds by accident of
what the GUI imports; from here it holds because a build that breaks it is not
swapped in.

**Messages a user can see name the window, not a command.** A notice that says
"run `logarc enrich`" or "rebuild with `logarc setup-crs`" names the menu or
button instead. Messages only a developer can reach, such as a source
checkout's missing sidecar, name `logarc-dev setup-crs`.

## Consequences

- **logarc can no longer run without a screen** for anyone but a developer: no
  scripted ingest on a server, no batch export. Accepted by the user on
  2026-10-17 ("so it's all gonna be a GUI now").
- Five commands, the `formats` group and their tests go: 821 of the command
  line's 1,699 lines. What they exercised is still exercised through the
  window's tests and the engine's own.
- Every document that shows a command changes: user documents drop them,
  developer documents (`docs/evaluation.md`, `docs/writing-rules.md`,
  `docs/adding-a-parser.md`, the rule-pack ledger) say `logarc-dev`. Records
  already written, this directory and `CHANGELOG.md` included, keep the
  command names they were written with.
- A source checkout still works exactly as before for development; only the
  command's name and its user-facing half change.

## Rejected

- **Delete the command line entirely.** It would remove the only way the
  project's published figures can be re-derived and the only way a source
  checkout gets CRS. Moving those into the window would build developer tasks
  into the product to save a terminal nobody but a developer opens.
- **Keep all twelve commands and only stop advertising them.** Cheapest, and it
  keeps every feature built and tested twice, which is the cost this decision
  exists to stop paying.
- **Keep the name `logarc`.** A user who finds `logarc` on their path would
  reasonably take it for the product. `logarc-dev` says what it is.
