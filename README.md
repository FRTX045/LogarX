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

## Development

```bash
ruff check . && ruff format --check .
mypy src/logarc
pytest --cov=logarc --cov-report=term-missing
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — layers, data flow, extension points
- [docs/adr/](docs/adr/) — architecture decision records

## License

MIT — see [LICENSE](LICENSE).
