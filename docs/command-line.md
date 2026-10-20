# The command line

The window is how logarc is used ([ADR-0012](adr/0012-the-window-is-the-product.md)).
The command line is developer tooling: it is how this project builds cases and
measures itself, and `evaluate`, `score-crs` and `benchmark` produce every
published figure. At the first public release it is renamed `logarc-dev`, and
the commands that only repeat the window are removed; the ADR lists which.

## A walk-through on the bundled log

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

# 1. Read the log into a case. The format is detected; nothing is configured.
#    --no-crs skips the OWASP CRS replay, which needs a one-time setup first.
logarc ingest tests/data/apache-shopfront/excerpt.log --case ./case-shop --no-crs

# 2. Who looks like they were probing? Sort by the share of 4xx responses.
logarc list-ips --case ./case-shop --sort errors --limit 8

# 3. Reconstruct one of them.
logarc analyze --case ./case-shop --ip 192.0.2.31

# 4. Read the log lines that finding rests on.
logarc evidence --case ./case-shop --ip 192.0.2.31 --limit 3

# 5. A standalone HTML report, or the desktop application.
logarc export --case ./case-shop --ip 192.0.2.31 --format html --out report.html
logarc-gui
```

Step 3 prints this:

![logarc analyze reduces 48 requests to 3 activities, the last 46 requests of successful SQL injection](images/cli-analyze.png)

Forty-eight requests, three sessions, three activities — and the one that matters,
46 requests of SQL injection, is named, dated, mapped to OWASP, and marked
`success` rather than `blocked`. The first line says CRS was not consulted;
[installing.md](installing.md#owasp-crs) sets it up.

Step 4 shows why you can believe it:

![logarc evidence prints the raw log lines behind each activity](images/cli-evidence.png)

## Commands

![logarc ingest reads 3,825 lines with nothing quarantined](images/cli-ingest.png)

| Command | What it does |
|---|---|
| `logarc ingest` | Read logs into a case, then replay it through OWASP CRS (`--no-crs` skips that). Streaming; memory is bounded by batch size, not file size. `--workers N` spreads the parse across processes. |
| `logarc list-ips` | List the clients seen. `--sort errors` ranks by the share of 4xx, which is what probing looks like. Also `requests`, `recent`, `bytes`, `paths`. |
| `logarc analyze` | Reconstruct one client's activity as a graph. `--out` writes it as JSON. |
| `logarc evidence` | The raw log lines a finding rests on — the other half of the chain of custody. |
| `logarc export` | A standalone HTML or JSON report for one client. |
| `logarc enrich` | Run OWASP CRS over a case again, or at another paranoia level. |
| `logarc setup-crs` | From a source checkout: fetch the pinned CRS ruleset and build the sidecar, once. |
| `logarc formats` | See, write and try out log formats. |
| `logarc evaluate` | Measure the reconstruction against a log whose content is known. |
| `logarc benchmark` | Throughput, peak memory and reconstruction time, on a log you give it. |
| `logarc convert-csic` | Turn the CSIC 2010 dataset into an access log logarc can read. |

![logarc list-ips ranked by the share of 4xx responses](images/cli-list-ips.png)
