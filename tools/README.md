# Developer tools

Tools for working on logarc. Nothing here is part of the application.

| | What it is for |
|---|---|
| [`local-ci.sh`](local-ci.sh) | Run the CI workflow's jobs on your machine. See *The whole CI, locally* in [CONTRIBUTING.md](../CONTRIBUTING.md#the-whole-ci-locally). |
| [`hooks/`](hooks/) | Git hooks: stop a commit CI would reject, keep `dist/` built. |
| [`regen-crs-corpus.sh`](regen-crs-corpus.sh) | Rewrite the CRS corpus record from a complete clone. |
| [`measure/`](measure/) | Measure the CRS sidecar: replay time, start-up time, memory, how responsive the window stays. |

## Git hooks

```bash
git config core.hooksPath tools/hooks
```

| Hook | What it does |
|---|---|
| `pre-commit` | Runs `ruff check` and `ruff format --check` over the whole tree, as CI's lint job does, and stops the commit if either fails. Uses `.venv`'s ruff so it agrees with CI on the version; without a `.venv` it says so and lets the commit through. `git commit --no-verify` commits anyway. |
| `post-merge` | Rebuilds `dist/` in the background when a merge into `main` (a `git pull` included) changed `src/logarc/`, `packaging/` or `pyproject.toml`. |
| `post-commit` | The same for a commit made directly on `main`, which fires no merge. A commit on any other branch waits for its merge, so a branch rebuilds once, not once per commit. |
| `post-checkout` | Prints the last rebuild failure, if there is one. `post-commit` does too. |

The rebuilds are off unless you ask for them, because they only make sense on
a Windows machine that builds the application:

```bash
git config logarc.rebuild true
```

They run `packaging/rebuild.py`, which tests, builds into a staging directory
and only then replaces `dist/logarc`. So a failed build leaves the previous
application in place. Their output goes to `~/.cache/logarc-build.log`, and
`dist/BUILD-STATUS.txt` says what the last build did.

`core.hooksPath` replaces `.git/hooks`. If you already have hooks there, they
stop running; call these from them instead.

## The CRS corpus record

```bash
tools/regen-crs-corpus.sh            # for HEAD
tools/regen-crs-corpus.sh my-branch  # or any ref
```

`tests/detect/crs/test_corpus_detections.py` replays every request in CRS's
regression corpus through the sidecar and compares the result with
`tests/data/crs-corpus-detections.json`. After a change that is meant to change
what CRS reports, such as a ruleset or Coraza upgrade, the record has to be
written again.

On Linux, `python tests/detect/crs/test_corpus_detections.py` does that. On
Windows, a virus scanner removes some corpus files (PHP and web-shell samples)
from the checkout, and the generator refuses an incomplete corpus. This script
works around that. It clones CRS fresh inside a Linux container, at the commit
CI pins, builds the sidecar there, writes the record, runs the test against it,
and copies only the record back.

It records the commit, not your working tree. Read the per-rule diff before you
commit the new record: a changed count is a changed detection. It needs Docker,
and uses the image and caches `local-ci.sh` builds.

## Measuring the sidecar

The figures in [`crs/README.md`](../crs/README.md#regular-expressions-re2)
were taken with earlier copies of these, by the same method, with one
difference: start-up was timed to the sidecar's first answer, and
`crs_startup.py` times it to the sidecar's exit. That reads about 0.02 s
higher: 0.33 s against 0.31 s for the same build, on 2026-10-17.

Each runs from a source checkout's environment (`pip install -e ".[gui]"`) and
takes the sidecar build and ruleset from the checkout unless told otherwise.

```bash
# Replay time: every build at every worker count, in an order that rotates each
# round, then each one's median and whether every run found the same detections.
python tools/measure/crs_replay.py CASE --binary old.exe --binary new.exe --workers 6 --rounds 3

# Start-up: one sidecar started, sent one request and stopped, ten times.
python tools/measure/crs_startup.py --binary new.exe

# Responsiveness: how late a 20 ms timer in a Qt window fires while a replay
# runs in a thread, and the same with nothing running, for comparison.
python tools/measure/ui_latency.py CASE
python tools/measure/ui_latency.py --idle 20
```

Memory, on Windows: start the sampler, run a replay, then stop it.

```powershell
powershell -ExecutionPolicy Bypass -File tools\measure\memsample.ps1 -Name crs-sidecar -Out C:\tmp\mem.txt
# ... run crs_replay.py in another terminal ...
echo stop > C:\tmp\mem.txt.stop
python tools\measure\memsum.py C:\tmp\mem.txt
```

A case is a directory made by the application or by `logarc ingest`. Close
other heavy programs while measuring, and compare builds within one run of
`crs_replay.py`, not across runs: the rotation is what makes two builds'
figures comparable.
