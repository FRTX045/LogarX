# ADR-0013: A reader's rules live in their settings and reach the engine as data

- **Status:** Accepted
- **Date:** 2026-10-21

## Context

Detection rules are YAML packs (ADR-0001's detection layer). Until now a reader
could add their own only through the command line's `--rules`, and the window
always used the 107 built-in rules. ADR-0012 makes the command line a developer
tool at the first release, so without a way in from the window, a reader of the
packaged application has no route to rules of their own at all.

Three readings of a case use rules, and they must agree: the client on screen,
the HTML report made from it, and *Where to start*, which a spawned process
works out. All three called `Case.rule_engine()` with nothing, so they agreed
trivially. A reader's rules break that unless every one of them gets the same
rules.

Two smaller facts mattered too. The command line's own documentation said a
pack reusing a built-in rule's id was refused, and it was not: ids were checked
only between the packs given on the command line, so a copy of
`sqli_union_select` loaded beside the real one. And a reader who finds one
built-in rule wrong for their site had no way to turn it off short of copying
its whole pack, which would then collide with every built-in id.

## Decision

- **Packs live in the reader's settings**, `<logarc_home>/rules/<name>.yaml`,
  beside the saved-format library and moved by the same `LOGARC_HOME`. The
  built-in rules a reader switched off are listed in
  `<logarc_home>/rules/switched-off.json`. Every case the reader opens is read
  with them.
- **They reach the engine as data, not as a path.** The window reads the folder
  (`rules_library.in_force()`) and holds the result as a `RuleSet`: the packs'
  text and the switched-off ids, frozen and picklable. It hands that one value
  to the reconstruction, the export and the scan, and the scan worker receives
  it as an argument, as it receives the time window. This is the move ADR-0010
  made for formats: a spawned process must use what the window holds, not
  whatever a file says by the time it gets round to reading it.
- **One place builds the rules**, `detect.ruleset.build_rules`, called by
  `Case.rule_engine`: the built-in rules less the switched-off ids, then each
  pack's. It refuses an id that a built-in rule still in force has, or that
  another pack has, naming both. Switching a built-in rule off frees its id, so a
  reader can replace it. The command line's `--rules` goes through the same
  function, which is what fixes the duplicate check there.
- **The command line never reads the folder.** `analyze`, `evidence`, `export`
  and `score-crs` keep `--rules`, which names its packs explicitly; without it,
  and always for `evaluate` and the published scores, the built-in rules alone
  apply.
- **A report names the rules**, beside the fingerprint that proves them: how
  many built-in rules, which were switched off, and each pack added, by name.
- **A pack in the folder that does not load is left out and named**, never
  deleted or rewritten. The other packs and every built-in rule still apply.

## Consequences

- The window, *Where to start* and a report cannot disagree about which rules a
  finding came from: they are handed the same `RuleSet`, and the engine's
  fingerprint covers every rule loaded. *Where to start* keys its cached scan on
  that fingerprint, so a change of rules gets a fresh scan and the one before
  stays on disk.
- A personal pack cannot move a published score. The measurement commands do
  not know the folder exists.
- **A case does not carry the rules that read it.** Opened on another machine,
  it is read with that reader's rules. The report says which rules produced it,
  by name and fingerprint, so two reports of one case made with different rules
  say so; but the pack itself is not in the case. That is the cost of the choice
  below.
- Changing rules while a case is open does not re-read it behind the reader's
  back. The rules tab asks, and a reader who says *Later* sees a strip in the
  window until the case is read again.
- The rules tab counts what a pack finds by labelling every client of the open
  case with the pack's rules alone. That is exact, because no rule's label
  depends on another rule's, and it is what lets a two-rule pack count a
  235,732-line case in about 6 seconds. A 24-rule built-in pack took 64.

## Alternatives considered

- **Packs inside each case**, as a case records the format that read it. A case
  would then carry the rules that produced its findings to another machine.
  Rejected because a reader writes a rule about their own site once and expects
  it in every case they open, and because a rule changed in one case and not
  the next is two answers to one question. The report naming the rules gives
  most of the traceability without it.
- **The engine reads the folder itself.** One line instead of a value passed
  through four call sites. Rejected because then every engine, including the
  ones `evaluate` and `score-crs` build, would silently include a personal pack,
  and the scan worker would read the folder at a different moment from the
  window.
- **Copying a built-in pack to edit it.** Rejected: the copy reuses every
  built-in id, so it could only be allowed by letting a later pack shadow an
  earlier one, which makes the result depend on load order. Switching one rule
  off and writing its replacement does the same job without that.
