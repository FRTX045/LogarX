# logarc — Log Activity Reconstruction

Forensic (offline) reconstruction of what a given IP address actually *did* on a web server,
recovered from access logs and rendered as an **activity graph**.

> **Status:** early development. See [docs/](docs/) for the design and architecture decisions.

---

## The problem

A web server access log is a flat list of requests. To understand what one visitor did, an
investigator reads thousands of lines by hand — slow, error-prone, and not reproducible.

`logarc` turns that list into a small number of **meaningful activities** and connects them
into a directed graph, so the log reads as a map of behaviour:

```
  browsing  →  reconnaissance  →  directory enumeration  →  SQL injection probing  →  data access
```

Each box is an *activity episode*; each arrow is an observed transition. Every box links back to
the exact raw log lines that produced it.

## The research question

> How do you separate one action from another, and then classify it — at log sizes measured in
> gigabytes, offline?

`logarc` answers this with **deterministic three-level segmentation** and a **two-pass ingest
architecture**. Both are described in [docs/architecture.md](docs/architecture.md).

Determinism is a deliberate constraint, not a limitation: a forensic finding must be explainable
and reproducible. Every boundary the tool draws can be traced to a stated rule and a recorded
threshold.

## Scope

| | |
|---|---|
| **Input** | Apache access logs (Combined, Common, and any custom `LogFormat` directive) |
| **Designed for** | nginx, IIS W3C and JSON logs — added as parser plugins, no core changes |
| **Detects** | OWASP Top 10 categories observable in access logs, plus benign context activity |
| **Runs** | Offline. Evidence never leaves the machine. |

### A note on OWASP Top 10 coverage

OWASP Top 10 is a taxonomy of *vulnerabilities*, not *behaviours*. Only part of it leaves a trace
in an access log:

| Observable | Not observable from access logs |
|---|---|
| A01 Broken Access Control | A02 Cryptographic Failures |
| A03 Injection | A04 Insecure Design |
| A05 Security Misconfiguration | A08 Software & Data Integrity Failures |
| A07 Identification & Auth Failures | A09 Security Logging & Monitoring Failures |
| A06 Vulnerable Components *(partial)* | |
| A10 SSRF *(partial)* | |

`logarc` therefore classifies **observable behaviour** and maps it *onto* OWASP as an attribute,
rather than forcing the taxonomy to be the structure. Coverage is reported honestly rather than
inflated.

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/FRTX045/BlackHat.git
cd BlackHat
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e ".[dev,gui]"
```

## Usage

```bash
# Ingest a log into a case directory (streaming; memory is bounded by batch size, not file size)
logarc ingest access.log --case ./case-001

# Parse across processes on a large log. Faster, and costs memory in step with
# the worker count — which is why it is opt-in rather than the default.
logarc ingest access.log --case ./case-001 --workers 4

# List the IPs seen, ranked by how suspicious their traffic looks
logarc list-ips --case ./case-001 --sort suspicion

# Reconstruct one IP's activity graph
logarc analyze --case ./case-001 --ip 203.0.113.45 --out graph.json

# Produce a self-contained HTML report for the case file
logarc export --case ./case-001 --ip 203.0.113.45 --format html --out report.html
```

### The desktop application

```bash
logarc-gui
```

![The logarc window: client list, session trace, and the log lines behind the selected activity](docs/images/screenshot-trace.png)

*Session trace — what happened, in order. A scanner's 61 requests reduced to 10 activities. Long
chains wrap onto further rows, alternating direction, because a trace drawn on one line is as wide
as it is long and shrinks to an unreadable smudge when fitted to the window. **View → Wrap long
traces** (Alt+Z) turns the fold off when the straight timeline is worth more than legible captions;
the graph is then panned rather than fitted, opening on its first activity, and the choice is
remembered between launches. The panel on the right is the evidence the selected node was built
from, a row per request: sort it by size to find the one that got data out, or by status to find
what was served rather than refused. Payloads are decoded, so `' OR '1'='1` reads as the tautology
it is instead of `%27+OR+%271%27%3D%271`. The pane beneath holds the selected request in full,
including the source line exactly as the log holds it — every finding traces back to a line.*

![The same client drawn as a behaviour map](docs/images/screenshot-behaviour.png)

*Behaviour map — the same reconstruction folded by activity type, so repetition becomes structure.
The four `Directory Enumeration` episodes of the trace are one 45-request node here, and the `x3` on
each arrow says the scanner went round that loop three times — the thing the trace cannot show. The
ring marks the activity whose evidence is open; the key along the bottom says what colour, outline
and size each mean.*

A Windows GUI (PyQt6) wraps the same engine — the CLI and the GUI share one code path, so
anything the GUI can do is scriptable. Pick a client from the table, read the activity graph,
click a node to see the raw log lines that node was built from, and export the same report the
CLI produces. Long work runs on a worker thread and can be cancelled; a cancelled ingest leaves
the case un-finalised, so a partial read can never be analysed as if it were complete.

The case you were last working on reopens when the window does, and **Case → Recently opened…**
(Ctrl+Shift+O) offers the others; **View → Reopen the last case on start** turns the first part off.

**That list is kept on the machine you are working at.** It records which cases were opened
here — their folders, when, and how much was in them — under `HKCU\Software\logarc`, beside the
view preferences. That is a record of what was investigated, not merely of how the window looked,
so the chooser carries a **Forget these** button that removes it.

It is verified by hand against [docs/manual-test-plan.md](docs/manual-test-plan.md) — whether the
node you clicked is the one whose evidence appeared is a judgement about what a person sees.
The decisions that determine whether a graph *misinforms* are kept out of Qt, in
`logarc.gui.style`, and tested directly.

### Checking that it works

Accuracy is measured against logs whose contents are known, because real logs cannot be:
nobody knows what is in them, which is the problem this tool exists to solve.

```bash
# Write a synthetic log together with a record of what is in it
logarc generate --scenario sqli_campaign --lines 200000 -o sample.log -t sample.truth.jsonl
logarc ingest sample.log --case ./case-demo

# Precision, recall and F1 per activity, and how well the boundaries were found
logarc evaluate --case ./case-demo --truth sample.truth.jsonl --out scores.json

# The same, with noise absorption off, to see what the merge rule costs
logarc evaluate --case ./case-demo --truth sample.truth.jsonl --no-absorb

# Throughput, peak memory and reconstruction latency by corpus size
logarc benchmark --lines 100000 --lines 1000000 --lines 10000000 --out bench.json

# Convert the CSIC 2010 dataset and score against it
logarc convert-csic --normal normalTrafficTest.txt --anomalous anomalousTrafficTest.txt \
    -o csic.log -t csic.truth.jsonl
```

### OWASP CRS

The bundled rules classify *behaviour*; OWASP CRS enumerates payload *syntax*, which is a different
job and one it does far better. Both run, and CRS never overrides a rule that examined the request —
it names the ones nothing else recognised.

```bash
cd crs && go build -o crs-sidecar .    # once; see crs/README.md
logarc enrich --case ./case            # replay the case past CRS
```

Optional. Without it a case analyses on the bundled rules alone, and says so on every run.

Measured results, and what they do and do not establish, are in
[docs/evaluation.md](docs/evaluation.md).

## Development

```bash
ruff check . && ruff format --check .
mypy src/logarc
mypy --platform linux src/logarc    # CI runs on both; some code is platform-shaped
pytest --cov=logarc --cov-report=term-missing
```

The second type check is not redundant. `mypy` analyses for the platform it runs
on, so a Windows-only branch guarded by `sys.platform` is skipped on Windows and
checked on Linux — and the reverse. Checking one platform passes code that the
other rejects.

### Building the Windows bundle

```bash
pip install -e ".[gui,package]"
python packaging/rebuild.py
```

Produces `dist/logarc/` (~250 MB), which runs without Python installed. One folder rather than
one file: a one-file build unpacks the whole bundle to `%TEMP%` on every launch, which with Qt
and Arrow in it costs seconds each time and leaves copies of the tool behind.

`rebuild.py` rather than `pyinstaller` directly, because **PyInstaller exits 0 on a bundle that is
missing what it could not see.** Two things a freezer drops silently, and the spec therefore
carries explicitly: the rule packs, which are data that nothing imports, and the package metadata,
which is where the case manifest gets the tool version it records. Both fail at runtime rather than
at build time, and the first fails *quietly* — no rules means every request reads as benign. The
script runs the tests, builds into a staging directory, checks for both of those and for a browser
engine that ADR-0006 says must not be there, and only then swaps the result into place. A red suite
or a failed check leaves the working bundle exactly where it was.

```bash
cat dist/BUILD-STATUS.txt      # what the last build did, and to which commit
pyinstaller --clean --noconfirm packaging/logarc.spec   # the raw build, unchecked
```

Check 7 of the manual test plan covers the same ground on the packaged result.

## Documentation

- [docs/architecture.md](docs/architecture.md) — layers, data flow, extension points
- [docs/writing-rules.md](docs/writing-rules.md) — adding detection without writing Python
- [docs/adding-a-parser.md](docs/adding-a-parser.md) — supporting another log format
- [docs/evaluation.md](docs/evaluation.md) — how accuracy is measured, the numbers, and their limits
- [docs/manual-test-plan.md](docs/manual-test-plan.md) — what the automated suite cannot check
- [docs/adr/](docs/adr/) — architecture decision records
- [CHANGELOG.md](CHANGELOG.md) — what is in this release, including what falls short

## License

MIT — see [LICENSE](LICENSE).
