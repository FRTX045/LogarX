# Contributing to Zodiarc

## How to help

Contributions are open. Each of these is welcome:

- **A bug**, including a log Zodiarc should read and does not: open an issue
  with the [bug report form](https://github.com/FRTX045/Zodiarc/issues/new/choose).
  The smallest log that shows the problem is worth more than any description.
- **A log format Zodiarc does not read yet**: the
  [new log format form](https://github.com/FRTX045/Zodiarc/issues/new/choose), with a
  few lines of the log and, if you know it, the server's log configuration.
- **A feature**: the [feature request form](https://github.com/FRTX045/Zodiarc/issues/new/choose).
  Say what you were trying to find out from a log, not only what to add.
- **A pull request**: open an issue first for anything larger than a fix, so the
  approach can be agreed before the work is done.
- **A vulnerability**: report it privately, as [SECURITY.md](SECURITY.md)
  describes. Never in a public issue.
- **A question or an idea**: [Discussions](https://github.com/FRTX045/Zodiarc/discussions).

Everyone taking part agrees to the [code of conduct](CODE_OF_CONDUCT.md).

The rest of this guide is how the project is worked on, for whoever works on it.

## Setting up

Requires Python 3.11 or newer.

```bash
git clone https://github.com/FRTX045/Zodiarc.git
cd zodiarc
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate         # Linux and macOS
pip install -e ".[gui,dev]"
```

OWASP CRS runs as a separate Go program. To build it from a checkout, see
[docs/installing.md](docs/installing.md#owasp-crs); without it the tests that
need it are skipped and a case analyses on the bundled rules alone.

## Checks

```bash
ruff check . && ruff format --check .
mypy src/zodiarc
mypy --platform linux src/zodiarc    # not redundant — some code is platform-shaped
pytest --cov=zodiarc --cov-report=term-missing
```

The second type check matters: `mypy` analyses for the platform it runs on, so a
Windows-only branch guarded by `sys.platform` is skipped on Windows and checked
on Linux, and the reverse.

`pytest`'s default temp root is unwritable on some Windows machines; set
`PYTEST_DEBUG_TEMPROOT` to a short writable path if the suite fails to start.

The four CRS contract tests skip without the Go binary. `ZODIARC_REQUIRE_CRS=1`
turns that skip into a failure; CI sets it.

### The whole CI, locally

```bash
tools/local-ci.sh              # the commit at HEAD
tools/local-ci.sh my-branch    # or any ref
```

Runs the jobs of `.github/workflows/ci.yml` on your machine: lint and both
type checks in a Linux container, the test suite on Linux in Docker for each
Python version the workflow lists, and on Windows natively when run from Git
Bash. Every test job builds the CRS sidecar, requires it, and holds the 94%
coverage floor. It tests the commit, not your working tree, and gives each run
fresh environments, so it passes or fails as a clean runner would.

It reads the Python versions and the CRS pin from the workflow rather than
repeating them, so the two cannot drift, and `tests/test_local_ci.py` checks
that. Needs Docker, [uv](https://docs.astral.sh/uv/), the ruleset clone in
[docs/installing.md](docs/installing.md#owasp-crs),
and on Windows Git Bash and Go 1.25+. A summary is printed and kept under
`~/.cache/zodiarc-ci/runs/` (`ZODIARC_CI_DIR` moves it). Exit 0 means every job
passed; 3 means nothing failed but some jobs could not run on this machine.

### Git hooks and the other tools

```bash
git config core.hooksPath tools/hooks
```

Stops a commit that CI's lint job would reject. [tools/README.md](tools/README.md)
describes the hooks and the rest of `tools/`: an opt-in rebuild of `dist/` when
work lands on `main`, a script that rewrites the CRS corpus record from a
complete clone, and the scripts that measured the CRS sidecar.

## How a change is made

- **Test first.** Write the test, run it, and watch it fail for the reason you
  expect, then write the code. A test that passes the moment it is written has
  not shown it can fail: break the code on purpose and check that it does.
- **One logical change per commit**, in [Conventional Commits](https://www.conventionalcommits.org/)
  form: `feat(gui): …`, `fix(storage): …`, `docs: …`.
- **A short-lived branch per change**, merged by pull request once CI is green
  on it.
- **Every finding traces to a log line.** `EvidenceRef` is the point of the
  tool, not plumbing: a result that cannot say which line produced it is not
  finished.
- **Measurements are reported as they came out.** A number that looks like a
  result and is not one is the worst thing this tool can emit, and the same
  goes for its documentation. A target that was missed is written down, not
  restated.

## Changing detection

Detection rules are YAML; [docs/writing-rules.md](docs/writing-rules.md)
describes them. A rule is finished when two numbers have moved the right way:
how much it catches of a corpus this project did not write, and how often it
fires on the traffic that corpus certifies as harmless and on the real server
log in `tests/data/apache-shopfront/`. A pack reaches any recall by matching
everything; the second number is what stops that scoring well.
[docs/rule-pack-ledger.md](docs/rule-pack-ledger.md) records every pass, what it
scored, and what was tried and did not work.

## Supporting another log format

Most formats need no code at all: [docs/log-formats.md](docs/log-formats.md)
shows the four kinds a reader can write. When one does need a parser,
[docs/adding-a-parser.md](docs/adding-a-parser.md) says how.

## Documentation

User-facing changes go in [CHANGELOG.md](CHANGELOG.md) and in the document
that describes them, listed in [docs/README.md](docs/README.md). A decision
that would be expensive to reverse gets a record in [docs/adr/](docs/adr/):
what was chosen, what it cost, and what was rejected.
