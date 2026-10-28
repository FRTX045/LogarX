# Sample logs

Two logs here work from a fresh clone: `demo/demo.log`, written to show every
feature, and a 3,825-line excerpt of a real build, committed under
`tests/data/apache-shopfront/` with its answer key and its scores. The
[quick start](#quick-start-on-what-is-in-the-repository) below uses them. The
rest of this page is about the full builds, which are not in the repository
and are downloaded from the dataset's releases.

The full builds are real logs, with the answer key. Everything under `samples/apache-shopfront/` is
a build of the LogarX Dataset `apache-shopfront` project: a real Apache 2.4
serving a real PHP shop, driven by scripted shoppers and crawlers, a real
Chromium for some sessions, real security tools and six scripted attack
campaigns, with every log line joined to a record of which client made it and
why. Nothing in it was written by a template.

The files are not in this repository. The numbers in
[docs/evaluation.md](../docs/evaluation.md) are tied to the exact bytes, so
they are pinned by checksum rather than versioned, and the builds they were
measured on are published as releases of the dataset: see
[Getting them](#getting-them).

## Quick start, on what is in the repository

The two logs that are committed, so they work from a fresh clone:
`samples/demo/demo.log` to see what the tool does, and the 3,825-line excerpt of
a real build under `tests/data/apache-shopfront/`, with its answer key, to check
how well it does it.

```powershell
logarx-dev ingest samples\demo\demo.log --format apache-vhost-combined --case .\case-demo
logarx-gui                      # Case -> Open, pick case-demo
```

Or all in the application: **Case → New from logs…**, pick a log, pick an
empty folder, then click a client in the table.

## Checking the answers

```powershell
logarx-dev ingest   tests\data\apache-shopfront\excerpt.log --case .\case-excerpt --no-crs
logarx-dev enrich   --case .\case-excerpt
logarx-dev evaluate --case .\case-excerpt --truth tests\data\apache-shopfront\excerpt.truth.jsonl
```

`enrich` replays the case through OWASP CRS; the headline figures include it, so
a run without it is a comparison rather than a result. The scores this prints
are committed beside the excerpt, and the same commands work on any build you
obtain. What the builds printed is in [docs/evaluation.md](../docs/evaluation.md).

## The builds

| Folder | Lines | Span | What it is for |
|---|---:|---|---|
| `apache-shopfront/2026-10-06-small/` | 63,310 | 1 day | The fast check. |
| `apache-shopfront/2026-10-06-medium/` | 235,732 | 7 days | **The headline evaluation**, in [docs/evaluation.md](../docs/evaluation.md). |
| `apache-shopfront/2026-10-06-large/` | 941,031 | 30 days | A month. |
| `apache-shopfront/2026-09-07-medium/` | 243,908 | 7 days | A past headline evaluation, and the build the committed excerpt was cut from. |
| `apache-shopfront/2026-08-23-small/` | 66,305 | 1 day | Past fast checks. |

The three `2026-10-06` builds are published. The two older ones are
**unobtainable** as of 2026-09-18 — see "Getting them" below before going
looking for them.

## `demo/` is the exception, and is not one of these

[`demo/demo.log`](demo/README.md) **was** written by a template — this project
wrote every line of it — and it is in the repository rather than pinned by
checksum, because a demonstration has to work the moment somebody opens it.

It is 841 lines and reaches all 107 detection rules, which the logs above do not:
they are real traffic, so they contain what real traffic contains and nothing
else. Use `demo/` to show what the tool can do. Use the committed excerpt, or a
build where you have one, to find out how well it does it, and never the other
way round, because scoring rules
against traffic written to suit them means nothing. `demo/` ships no truth file
for that reason.

Each folder holds `access.log`, `truth.jsonl`, `MANIFEST.json` (seed, dataset
commit, and every attack command line with its source address) and
`SHA256SUMS`.

## Getting them

**The `2026-10-06` builds are published,** one release per build on
[LogarX Dataset](https://github.com/FRTX045/LogarX-Dataset/releases), each tagged at
the commit that holds the build's manifest. Download one, unpack it and check it:

```bash
B=samples/apache-shopfront/2026-10-06-medium
gh release download 2026-10-06-medium -R FRTX045/LogarX-Dataset -D $B
(cd $B && xz -dk *.xz && sha256sum -c SHA256SUMS --ignore-missing)
```

The release is 3.5 MB small, 13 MB medium and 53 MB large, compressed. Every
file should print `OK`; `sha256sum` also warns about the comment lines in
`SHA256SUMS`, which is expected. The decompressed `access.log`, `truth.jsonl`
and `MANIFEST.json` have the digests
[docs/evaluation.md](../docs/evaluation.md) records, and each build's manifest
says the tree was clean when it was made.

**The two older builds cannot be obtained, and the steps below no longer
reach them.** Checked on 2026-09-18 against the GitHub API: that repository's
`datasets/apache-shopfront/` holds `2026-08-17-{small,medium,large}` and neither
of the folders named above. Following these steps lands you on a different build,
and the `sha256sum -c` then fails — correctly, because the bytes are not the ones
the figures were measured on.

The *generator* is another matter and is obtainable: the dataset commits recorded
in [docs/evaluation.md](../docs/evaluation.md) both exist, and `0485a9a6` is the
tip of that repository's default branch. An earlier version of this paragraph
said they did not exist; that was wrong and is corrected there in full. So the
rebuild route below can be attempted — it just produces a comparable corpus
rather than these bytes, for the reason given under it.

The method is unchanged and a newer build is worth having. Copy a folder from
[LogarX Dataset](https://github.com/FRTX045/LogarX-Dataset)'s
`datasets/apache-shopfront/`, then check it:

```bash
cd samples/apache-shopfront/<build> && sha256sum -c SHA256SUMS
```

Prefer a build whose `MANIFEST.json` records that the tree was clean when it was
made — otherwise the recorded commit does not determine the output and
`git checkout` reproduces something else. The `2026-10-06` builds do; the
`2026-08-17-{small,medium,large}` builds committed there each carry
`commit_is_clean: false`, checked on 2026-09-18.

A build can also be regenerated with the dataset's own
`tools/build.py apache-shopfront medium`, which needs Docker and about half an
hour. The same seed reproduces the same plan of requests, **not the same
bytes**: the campaigns react to a live server, and requests interleave
differently on every run. A regenerated build scores close to the pinned one,
not identically, and the evaluation doc says so rather than implying an
equality it cannot deliver.

**Watch the false-alarm rate.** A missed attack leaves an investigator where
they started; a false positive sends them to write up something that never
happened, and enough of them make the whole report untrustworthy. It is the
number a change to the rule packs most easily breaks.

## The test fixture

`tests/data/apache-shopfront/` holds a 3,825-line excerpt of the medium build,
committed and checksum-pinned, so the test suite has a real log to score
without needing either of the builds above. Its README says how it was cut.

## Real-world data with weaker labels

`logarx-dev convert-csic` turns the **CSIC 2010 HTTP dataset** — real traffic against
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
