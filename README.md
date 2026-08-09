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

# List the IPs seen, ranked by how suspicious their traffic looks
logarc list-ips --case ./case-001 --sort suspicion

# Reconstruct one IP's activity graph
logarc analyze --case ./case-001 --ip 203.0.113.45 --out graph.json

# Produce a self-contained HTML report for the case file
logarc export --case ./case-001 --ip 203.0.113.45 --format html --out report.html
```

A Windows GUI (PyQt6) wraps the same engine — the CLI and the GUI share one code path, so
anything the GUI can do is scriptable.

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

## Documentation

- [docs/architecture.md](docs/architecture.md) — layers, data flow, extension points
- [docs/evaluation.md](docs/evaluation.md) — how accuracy is measured, and the numbers
- [docs/adr/](docs/adr/) — architecture decision records

## License

MIT — see [LICENSE](LICENSE).
