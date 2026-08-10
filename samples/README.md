# Sample logs

Test data for exercising the application. Every file here was written by
`logarc generate` with a fixed seed, so anyone who runs the same command gets
byte-identical output and a result you can compare against.

Generated logs rather than a captured one on purpose: **nobody knows what is in
a real log.** That is the problem this tool exists to solve, so a real log can
show you the tool runs but cannot tell you whether it was right. Each log here
ships with a `.truth.jsonl` sidecar recording what was actually put in it,
written from the generator's own behaviour and never from the detection engine —
so scoring against it is not circular.

Everything below was run before being written down; the numbers are measured,
not expected.

## The files

| File | Lines | What it is | Use it for |
|---|---:|---|---|
| `mixed.log` | 50,000 | Everything at once — 2,491 clients, ordinary and hostile | The main demo. This is the case a real investigator is handed. |
| `sqli_campaign.log` | 30,000 | Recon, then injection, then one payload that returns data | The clearest story on the graph: an attack that *worked*. |
| `wordpress_scan.log` | 20,000 | Content discovery against a quiet site | Enumeration, and how noise absorption keeps it one episode. |
| `normal_browsing.log` | 20,000 | Shoppers and a search engine. Nothing hostile at all. | **The negative control.** Any hostile finding here is a false positive. |
| `brute_force.log` | 15,000 | Password guessing against the login endpoint | A window rule firing on what no single request reveals. |
| `path_traversal.log` | 15,000 | A download parameter walked out of the document root | Encoding evasion — the payloads are percent-encoded. |
| `compressed.log.gz` | 20,000 | `wordpress_scan` gzipped, 3.5 MB → 196 KB | That `.gz` is read transparently, with no manual step. |
| `damaged.log` | 5,005 | 3 malformed lines and 2 blank ones, mixed into real traffic | That damage is quarantined and counted, never dropped silently. |

## Quick start

```powershell
# ingest and look around
logarc ingest samples\mixed.log --case .\case-demo
logarc list-ips --case .\case-demo --sort requests --limit 20

# reconstruct the busiest client, then read the lines behind it
logarc analyze  --case .\case-demo --ip <address>
logarc evidence --case .\case-demo --ip <address>
```

In the application: **Case → Ingest logs into a new case…**, pick a log, pick an
empty folder, then click a client in the table.

## Checking the answers

```powershell
logarc evaluate --case .\case-demo --truth samples\mixed.truth.jsonl
```

On `mixed.log` at seed 7 this reports roughly:

```
accuracy 0.967   macro F1 0.959   weighted F1 0.966
Attack or not  precision 1.000  recall 0.994  false alarms 0.000%
```

**Precision 1.000 is the number to watch.** A missed attack leaves an
investigator where they started; a false positive sends them to write up
something that never happened, and enough of them make the whole report
untrustworthy. If a change to the rule packs moves that below 1.000, it is a
regression regardless of what it did for recall.

`normal_browsing.log` is the blunt version of the same check: it contains
nothing hostile, so anything the tool calls hostile there is wrong.

## Regenerating them

The logs themselves are not in the repository — 47 MB of generated data that a
single command reproduces is not worth versioning. The seed is what makes that
safe: the same command produces a **byte-identical log**, verified by hash.

The `.truth.jsonl` sidecars reproduce identically too, in every one of their
records. Only their first line differs between runs, because it is a header
carrying `generated_at` and the source filename — provenance about when the
truth was written, which is supposed to change.

```powershell
logarc generate -s mixed           -n 50000 --seed 7 -o samples\mixed.log           -t samples\mixed.truth.jsonl
logarc generate -s sqli_campaign   -n 30000 --seed 7 -o samples\sqli_campaign.log   -t samples\sqli_campaign.truth.jsonl
logarc generate -s normal_browsing -n 20000 --seed 7 -o samples\normal_browsing.log -t samples\normal_browsing.truth.jsonl
logarc generate -s wordpress_scan  -n 20000 --seed 7 -o samples\wordpress_scan.log  -t samples\wordpress_scan.truth.jsonl
logarc generate -s brute_force     -n 15000 --seed 7 -o samples\brute_force.log     -t samples\brute_force.truth.jsonl
logarc generate -s path_traversal  -n 15000 --seed 7 -o samples\path_traversal.log  -t samples\path_traversal.truth.jsonl
```

`compressed.log.gz` is `wordpress_scan.log` gzipped. `damaged.log` is
`sqli_campaign` at seed 11, 5,000 lines, with a truncated write, a rotation
marker, a request line missing its status, and two blank lines inserted into it.

## Bigger inputs

These are kept small enough to hand around. For the responsiveness and memory
checks in [docs/manual-test-plan.md](../docs/manual-test-plan.md), generate your
own — a million lines is about 200 MB, ten million about 2 GB:

```powershell
logarc generate -s mixed -n 1000000  -o big.log
logarc generate -s mixed -n 10000000 -o huge.log
```

## Real-world data

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
