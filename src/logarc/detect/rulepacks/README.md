# Rule packs

Data, not code. Detection is extended by adding YAML here, or by pointing
`--rules` at your own directory — never by touching the engine.

```
rulepacks/
├── attack/              what somebody did to the server
│   ├── global/          presumes no technology: loaded, relevant, everywhere
│   │   ├── injection.yaml   SQL, script, shell metacharacters, templates
│   │   ├── files.yaml       reaching a file, or leaving one behind
│   │   ├── access.yaml      admin areas, debug endpoints, version manifests
│   │   ├── ssrf.yaml        making the server fetch something
│   │   └── recon.yaml       who is asking, how often, for what
│   ├── php.yaml         only means something to a PHP runtime
│   ├── java.yaml        only means something to a JVM
│   └── shell.yaml       aimed at a Unix shell behind the web server
└── action/              what somebody did *with* the server
    ├── global.yaml      search, sign in, upload, submit — any site
    └── commerce.yaml    cart, checkout, payment — a site that sells
```

## Attacks are half of it

`action/` describes ordinary use, and it exists because "which of these
addresses was a customer?" is the question a person actually asks of a log with
fifty thousand clients in it — and no attack rule can answer it. `POST /checkout`
used to be reported as "Non-idempotent Request", which names the HTTP verb.

Three rules keep the two halves from interfering:

- **Action rules are `severity: info`.** A rule describing an attack always
  leads the report instead. `/search?q=' OR 1=1--` is an injection that happened
  to arrive at the search box, and it is reported as one.
- **A hostile label outranks a benign one at equal severity**, whatever the
  confidence. `Scripted Client` is INFO at 0.4 because a user-agent is a claim;
  `View Cart` is INFO at 0.85 because the path is a fact. The report still leads
  with the script.
- **Confidence orders what a reader sees.** An episode is named after its most
  significant label, so a run of forty product views containing one checkout is
  named "Checkout". The fallback ladder in `detect/engine.py` sits at 0.5 and
  still answers for everything no rule claimed.

## Two axes, and only one of them is a folder

A rule sits somewhere on two independent axes: **what it is about** (an attack,
or an ordinary use of the site) and **what it presumes about the stack** (PHP,
a JVM, or nothing at all).

The first is the folder. The second is the file name. The OWASP category is
neither — it is already inside every rule, on the `category:` line, so making
it a folder as well would give `php_code_execution` two homes that are equally
correct and force a coin-flip every time a rule is written.

Inside `global/` the technology axis is already spent, so the files there split
by subject instead. That is a convenience for reading, not a taxonomy.

## Everything loads, every time

There is no per-stack switch and there should not be. An attacker throwing PHP
at a Python backend has said what they were trying to do, and a request that
could never have worked is still evidence — often better evidence, because it
says they were guessing. `php.yaml` is a statement about what a pattern
*means*, not about when to look for it.

The folders are for the person editing them. The engine flattens all of it into
one list and tests every request against every rule.

## What is deliberately absent

Four OWASP Top 10 categories have no rules here and are not oversights.
**A02** (Cryptographic Failures), **A04** (Insecure Design), **A08** (Software
and Data Integrity Failures) and **A09** (Logging and Monitoring Failures) leave
no signature in a request line. Writing rules that pretend otherwise would
raise apparent coverage without detecting anything, which is worse than the gap.

## Writing one

Patterns are matched against normalised text — already percent-decoded
(recursively), Unicode-folded, case-folded and stripped of SQL comments. Write
the rule once, in canonical form, rather than once per evasion. Match the raw
`target` instead when the evidence *is* the encoding.

Rule ids are unique across every pack; the loader refuses a duplicate and names
both files. A directory with no packs in it is refused too, because zero rules
is not an answer.

Before adding a rule, and again after, run both scoreboards:

```bash
logarc score-crs --family 933        # a corpus this project did not write
pytest tests/evaluation              # the committed scores, guarded against drift
```

A rule that raises recall and also raises false alarms has not earned its place.
