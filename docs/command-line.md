# The developer tools

The window is how LogarX is used ([ADR-0012](adr/0012-the-window-is-the-product.md)).
`logarx-dev` is developer tooling: it is how this project builds cases and
measures itself, and `evaluate`, `score-crs` and `benchmark` produce every
published figure. It is installed with a source checkout and is not part of the
packaged application. Everything it shared with the window, from the client list
to reports and log formats, is in the window only.

## A walk-through on the bundled log

A real Apache log ships with the repository — 3,825 lines a real server wrote
while real attack tools were pointed at it — so this works in a fresh clone with
nothing downloaded.

```bash
git clone https://github.com/FRTX045/LogarX.git
cd logarx
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate         # Linux and macOS
pip install -e ".[gui,dev]"

# 1. Read the log into a case. The format is detected; nothing is configured.
#    --no-crs skips the OWASP CRS replay, which needs a one-time setup first.
logarx-dev ingest tests/data/apache-shopfront/excerpt.log --case ./case-shop --no-crs

# 2. Read it in the window: Case → Open, then the client list, the graph and
#    the evidence behind each activity.
logarx-gui

# 3. Measure it against the labels that ship with the log.
logarx-dev evaluate -c ./case-shop -t tests/data/apache-shopfront/excerpt.truth.jsonl --no-crs
```

## Commands

![logarx-dev ingest reads 3,825 lines with nothing quarantined](images/cli-ingest.png)

| Command | What it does |
|---|---|
| `logarx-dev ingest` | Read logs into a case, then replay it through OWASP CRS (`--no-crs` skips that). Streaming; memory is bounded by batch size, not file size. `--workers N` spreads the parse across processes. |
| `logarx-dev enrich` | Run OWASP CRS over a case again, or at another paranoia level. |
| `logarx-dev setup-crs` | From a source checkout: fetch the pinned CRS ruleset and build the sidecar, once. |
| `logarx-dev evaluate` | Measure the reconstruction against a log whose content is known. |
| `logarx-dev score-crs` | Score the rule packs against OWASP CRS's own regression corpus: what they catch, and what they flag that the corpus calls harmless. |
| `logarx-dev benchmark` | Throughput, peak memory and reconstruction time, on a log you give it. |
| `logarx-dev convert-csic` | Turn the CSIC 2010 dataset into an access log LogarX can read. |
