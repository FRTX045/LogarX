# logarc

**Reconstruct what one IP address actually did on a web server, from its access logs.**

[![CI](https://github.com/FRTX045/logarc/actions/workflows/ci.yml/badge.svg)](https://github.com/FRTX045/logarc/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Runs offline](https://img.shields.io/badge/runs-offline-informational)](#no-network-no-account-no-api-key)
[![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange)](#status)

An access log is a flat list of requests. Reading one visitor's story out of it
means reading thousands of lines by hand — slow, easy to get wrong, and not
reproducible by the next person. logarc turns that list into a small number of
**activity episodes** and connects them into a graph:

```
browsing → reconnaissance → directory enumeration → SQL injection → data access
```

Every box links back to the exact raw log lines that produced it.

![The logarc window: the client list, one client's trace with each session in a box, and the 46 log lines behind the selected SQL injection](docs/images/screenshot-trace.png)

<sub>sqlmap against a shop, in the last of three sessions. The selected activity is 46 requests — 30 `UNION ALL SELECT`, 11 always-true conditions, one column count, and four known only by sqlmap's user agent — and the outcome is **success**: the server answered 200 to every one. The panel on the right is the evidence: line numbers, statuses, and the raw line exactly as Apache wrote it.</sub>

---

## What it does

| | |
|---|---|
| **Reads** | Apache, nginx, IIS W3C, Caddy, Traefik, Cloudflare, Google Cloud, ECS, CloudFront — fourteen formats built in, plus any format you write yourself |
| **Finds** | OWASP Top 10 categories that are observable in an access log, plus the ordinary traffic between them |
| **Produces** | An activity graph per client, an HTML or JSON report, and a line-level evidence trail |
| **Runs** | Offline. Evidence never leaves the machine. |
| **Costs** | Nothing. MIT licensed. |

### No network, no account, no API key

logarc makes no outbound connections. Its runtime dependencies are pyarrow,
duckdb, pyyaml, pydantic, typer and rich — no cloud SDK, no model, no telemetry.
The OWASP CRS step, on by default, runs a local Go binary against a local copy
of the ruleset; it is not a service.

This matters because the input is a production access log, which is evidence.

---

## Quick start

A real Apache log ships with the repository — 3,825 lines a real server wrote
while real attack tools were pointed at it — so this works in a fresh clone with
nothing downloaded.

```bash
git clone https://github.com/FRTX045/logarc.git
cd logarc
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate         # Linux and macOS
pip install -e ".[gui]"
logarc-gui
```

Then, in the window:

1. **Case → Ingest logs into a new case…**, choose
   `tests/data/apache-shopfront/excerpt.log`, then an empty folder for the case.
   The format is detected; nothing is configured. On a fresh clone a notice
   then says **CRS is not installed**: the case is complete without it, so
   choose **Continue**. [docs/installing.md](docs/installing.md#owasp-crs) sets
   up that optional second ruleset.
2. **Where to start** lists the clients worth reading first, each with the
   measurements behind its place in the queue.
3. Click **192.0.2.31** in the client list. Its 48 requests, over three
   sessions, become three activities, and the last is 46 requests of SQL
   injection, every one answered with a 200.
4. Click an activity. The panel on the right lists the log lines it rests on,
   and shows each raw line exactly as the log holds it.
5. **Ctrl+D** bookmarks what you are looking at. **Export → HTML report…**
   writes a standalone report.

![557 requests folded into two activity types, with the wordlist behind the selected one](docs/images/screenshot-behaviour.png)

<sub>The **behaviour map** of another client, 192.0.2.231: the same reconstruction folded by activity type, so repetition becomes structure. Its 157 activities become two nodes, and `x45` and `x41` on the arrows say it switched from one to the other 45 times and back 41 times — the thing a chronological trace cannot show. The evidence panel holds all 355 requests of the selected one: `/admin.php`, `/vendor/…`, `/db.sql`, `/backup.zip`, `/shell.php` — a wordlist, being worked through.</sub>

Every screen is described in [docs/desktop-app.md](docs/desktop-app.md).

---

## How it refuses to lie to you

The failure this tool is built against is not a crash. It is a case that looks
complete and is not.

- **A log it cannot read is refused, not guessed at.** A wrong parser quarantines
  every line and presents as a clean, empty case.
- **Malformed lines are quarantined and counted, never dropped.** A case that
  could not read all of its logs says so every time it is opened.
- **A cancelled ingest leaves the case un-finalised**, so a partial read cannot be
  analysed as if it were whole.
- **An analysis that ran without CRS says so on every run**, rather than quietly
  reporting less.
- **A time format with no year is refused**, rather than dating every event 1900.
- **No progress estimate is shown until the read has settled**, and it always
  reads *about*.
- **`case.json` records a SHA-256 of every source file**, the format definition
  each was read with, and the CRS revision and settings. Each JSON export records
  the ruleset fingerprint and every threshold the analysis used, so a finding
  names the rules and settings that produced it.

---

## How well does it work

Measured on a real Apache log whose contents are known: the
[BlackHat-Dataset](https://github.com/FRTX045/BlackHat-Dataset) `apache-shopfront`
`2026-10-06-medium` build — 235,732 requests over seven days, a real PHP shop
driven by real security tools. Measured 2026-10-09, native rules only.

| | |
|---:|---|
| **0.997** | accuracy over 235,732 requests |
| **0.953** | macro F1 |
| **0 requests** | false alarms, in 235,732 |

Both numbers matter, and why the second is lower is part of the result: see
[docs/evaluation.md](docs/evaluation.md) for the method, the per-category figures
and every caveat.

---

## Installing

Requires **Python 3.11 or newer**. The engine is tested on Linux and Windows,
Python 3.11 and 3.12, on every push. The desktop application is built and
packaged for Windows, and runs on Linux.

```bash
pip install -e ".[gui]"      # the tool and the desktop application
pip install -e "."           # the command line alone
pip install -e ".[dev]"      # add the test and lint toolchain
```

There is no download yet. A Windows build that runs without Python can be made
from a checkout with `python packaging/rebuild.py`, and a ready-made one comes
with the first release. Linux display libraries, the packaged build and the
OWASP CRS sidecar are covered in [docs/installing.md](docs/installing.md).

---

## Documentation

| | |
|---|---|
| [docs/installing.md](docs/installing.md) | Installing, the packaged Windows build, and OWASP CRS |
| [docs/desktop-app.md](docs/desktop-app.md) | The desktop application, screen by screen |
| [docs/detection.md](docs/detection.md) | What it detects, and what its OWASP Top 10 annotations do and do not claim |
| [docs/log-formats.md](docs/log-formats.md) | The fourteen built-in formats, and writing your own |
| [docs/evaluation.md](docs/evaluation.md) | How accuracy is measured, the numbers, and their limits |
| [docs/architecture.md](docs/architecture.md) | How it separates one action from the next, layers and data flow |
| [docs/writing-rules.md](docs/writing-rules.md) | Adding detection without writing Python |
| [docs/adding-a-parser.md](docs/adding-a-parser.md) | Supporting another log format in code |
| [docs/command-line.md](docs/command-line.md) | The developer command line |
| [docs/adr/](docs/adr/) | The architecture decision records, including the ones that were wrong |
| [CHANGELOG.md](CHANGELOG.md) | What has changed, including what falls short |

---

## Status

Pre-release, version `0.3.0.dev0`. The engine and the desktop application work
and are tested on every push, but nothing has been released yet: there is no
download, and interfaces may still change. 0.1.0 and 0.2.0 in the
[changelog](CHANGELOG.md) are development milestones, not releases.

## Contributing

Contributions open with the first release. Until then:

- **Found a bug?** [Open an issue](https://github.com/FRTX045/logarc/issues/new/choose).
  The smallest log that shows it helps most.
- **Found a vulnerability?** Report it privately, as [SECURITY.md](SECURITY.md)
  describes.
- **A question or an idea?** Start a [discussion](https://github.com/FRTX045/logarc/discussions).

[CONTRIBUTING.md](CONTRIBUTING.md) has the development setup, the checks, and the
conventions the code follows. Everyone taking part agrees to the
[code of conduct](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE). Third-party notices in [NOTICE](NOTICE).
