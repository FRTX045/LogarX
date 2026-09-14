# Sample logs

Real logs, with the answer key. Everything under `samples/apache-shopfront/` is
a build of the BlackHat-Dataset `apache-shopfront` project: a real Apache 2.4
serving a real PHP shop, driven by scripted shoppers and crawlers, a real
Chromium for some sessions, real security tools and six scripted attack
campaigns, with every log line joined to a record of which client made it and
why. Nothing in it was written by a template.

The files are not in this repository. They are 22 MB and 80 MB for the whole
build — the log, its truth file and the manifest together — and the numbers
in [docs/evaluation.md](../docs/evaluation.md) are tied to the exact bytes, so
they are pinned by checksum rather than versioned.

## The builds

| Folder | Lines | Span | What it is for |
|---|---:|---|---|
| `apache-shopfront/2026-09-07-medium/` | 243,908 | 7 days | The headline evaluation. |
| `apache-shopfront/2026-08-23-small/` | 66,305 | 1 day | Fast checks and demos. |

Each folder holds `access.log`, `truth.jsonl`, `MANIFEST.json` (seed, dataset
commit, and every attack command line with its source address) and
`SHA256SUMS`.

## Getting them

Copy the folder from
[BlackHat-Dataset](https://github.com/FRTX045/BlackHat-Dataset)'s
`datasets/apache-shopfront/`, then check it:

```bash
cd samples/apache-shopfront/2026-09-07-medium && sha256sum -c SHA256SUMS
```

A build can also be regenerated with the dataset's own
`tools/build.py apache-shopfront medium`, which needs Docker and about half an
hour. The same seed reproduces the same plan of requests, **not the same
bytes**: the campaigns react to a live server, and requests interleave
differently on every run. A regenerated build scores close to the pinned one,
not identically, and the evaluation doc says so rather than implying an
equality it cannot deliver.

## Quick start

```powershell
logarc ingest samples\apache-shopfront\2026-08-23-small\access.log --case .\case-demo
logarc list-ips --case .\case-demo --sort requests --limit 20
logarc analyze  --case .\case-demo --ip <address>
logarc evidence --case .\case-demo --ip <address>
```

In the application: **Case → Ingest logs into a new case…**, pick a log, pick an
empty folder, then click a client in the table.

## Checking the answers

```powershell
logarc enrich   --case .\case-demo
logarc evaluate --case .\case-demo --truth samples\apache-shopfront\2026-08-23-small\truth.jsonl
```

`enrich` replays the case through OWASP CRS; the headline figures include it, so
a run without it is a comparison rather than a result. What this prints on each
build is in [docs/evaluation.md](../docs/evaluation.md).

**Watch the false-alarm rate.** A missed attack leaves an investigator where
they started; a false positive sends them to write up something that never
happened, and enough of them make the whole report untrustworthy. It is the
number a change to the rule packs most easily breaks.

## The test fixture

`tests/data/apache-shopfront/` holds a 3,825-line excerpt of the medium build,
committed and checksum-pinned, so the test suite has a real log to score
without needing either of the builds above. Its README says how it was cut.

## Real-world data with weaker labels

`logarc convert-csic` turns the **CSIC 2010 HTTP dataset** — real traffic against
a real application, labelled normal or anomalous — into an access log this tool
can read. It is not included here; you have to download it yourself.

Be aware of the ceiling before you read the score: a substantial share of CSIC's
attacks carry their payload in a **POST body**, and a web server access log
records the request line and nothing after it. Those are unreachable by
construction, not missed. `convert-csic` counts them in the copy you give it and
prints the resulting maximum recall, so the figure you quote is measured rather
than repeated from someone else. Outcome cannot be scored on CSIC at all — the
traces carry no responses, so attempt-versus-breach has nothing to compare to.

Classic public web logs (NASA-HTTP, ClarkNet, EPA-HTTP from the Internet Traffic
Archive) are useful for a different purpose: they are real, large, in Common Log
Format rather than Combined, and almost entirely benign. Good for testing format
detection and throughput. They carry no attack labels, so they cannot tell you
anything about accuracy.
