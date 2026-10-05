#!/usr/bin/env bash
# Run the jobs of .github/workflows/ci.yml on this machine.
#
#   tools/local-ci.sh [<git ref>]      test a commit (default: HEAD)
#   tools/local-ci.sh --print-matrix   show what was read from the workflow
#
# What runs, as the workflow has it:
#   lint and type checks   in a Linux container, as CI runs them on Ubuntu:
#                          ruff, ruff format, mypy, mypy --platform win32
#   tests on Linux         in Docker, one container per Python version
#   tests on Windows       natively, when this is Windows (Git Bash)
# Every test job builds the CRS sidecar, sets LOGARC_REQUIRE_CRS=1, runs the
# engine half with coverage and the window half with --cov-append, so the 94%
# floor in pyproject.toml applies; on Linux the window half is retried once on
# exit 139 only, as CI does.
#
# The Python versions and the CRS pin are read from the workflow, not repeated
# here, so the two cannot drift; tests/test_local_ci.py holds that.
#
# Needs: git, Docker, uv (https://docs.astral.sh/uv/), and on Windows Go 1.25+
# and Git Bash. The ruleset clone at vendor/coreruleset, at the pinned commit.
#
# Environment:
#   LOGARC_CI_DIR       where runs, environments and the worktree go
#                       (default ~/.cache/logarc-ci)
#   LOGARC_CI_TEMPROOT  pytest's temp root for the Windows jobs. Keep it short:
#                       a long one fails tests with WinError 3 (default
#                       $LOGARC_CI_DIR/tmp)
#
# Exit status: 0 every job passed; 1 a job failed; 2 could not start; 3 nothing
# failed but some jobs could not run here (no Docker, or no Windows). Only 0
# means the commit passed CI.
set -u

REPO=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel) || exit 2
WORKFLOW=$REPO/.github/workflows/ci.yml

PYTHONS=$(grep -m1 'python-version: \[' "$WORKFLOW" | sed 's/.*\[//; s/\].*//; s/[",]/ /g' | xargs)
LINT_PY=$(grep -m1 'python-version: "' "$WORKFLOW" | sed 's/.*"\(.*\)".*/\1/')
CRS_COMMIT=$(grep -m1 'CRS_COMMIT:' "$WORKFLOW" | awk '{print $2}')
if [ -z "$PYTHONS" ] || [ -z "$LINT_PY" ] || [ -z "$CRS_COMMIT" ]; then
  echo "could not read the matrix from $WORKFLOW"; exit 2
fi
if [ "${1:-}" = "--print-matrix" ]; then
  echo "python: $PYTHONS"
  echo "lint: $LINT_PY"
  echo "crs: $CRS_COMMIT"
  exit 0
fi

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac
winpath() { if [ "$WINDOWS" = 1 ]; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

CI_DIR=${LOGARC_CI_DIR:-$HOME/.cache/logarc-ci}
TEMPROOT=${LOGARC_CI_TEMPROOT:-$CI_DIR/tmp}
UV=$(command -v uv || echo "$HOME/.local/bin/uv")
GO=$(command -v go || echo "/c/Program Files/Go/bin/go.exe")
HAVE_DOCKER=1; command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || HAVE_DOCKER=0

REF=${1:-HEAD}
cd "$REPO" || exit 2
SHA=$(git rev-parse --verify "$REF^{commit}") || exit 2
SHORT=${SHA:0:7}
RUN=$CI_DIR/runs/$SHORT
rm -rf "$RUN" && mkdir -p "$RUN" "$TEMPROOT" || exit 2
echo "local CI for $REF at $SHORT -> $RUN"

# The ruleset CI pins, or nothing: a different revision is a different test.
RULESET=$REPO/vendor/coreruleset
if [ "$(git -C "$RULESET" rev-parse HEAD 2>/dev/null)" != "$CRS_COMMIT" ]; then
  echo "vendor/coreruleset must be a clone at $CRS_COMMIT (see the README's OWASP CRS section)"; exit 2
fi
RULES_BEFORE=$(ls "$RULESET/rules" | wc -l)

record() { echo "$2" > "$RUN/$1.exit"; }

# -- Linux: lint, type checks and tests, in containers --------------------------
image() {  # image <python version>
  MSYS_NO_PATHCONV=1 docker build -q -t "logarc-ci:$1" --build-arg "PY=$1" \
    -f "$(winpath "$REPO/tools/local-ci.Dockerfile")" "$(winpath "$REPO/tools")"
}

in_container() {  # in_container <python version> <script> ; the commit is at /src
  git -C "$REPO" archive "$SHA" | MSYS_NO_PATHCONV=1 docker run -i --rm \
    -v "$(winpath "$RULESET"):/ruleset:ro" \
    -v logarc-ci-uv:/root/.cache/uv -v logarc-ci-go:/root/go \
    -e LOGARC_REQUIRE_CRS=1 "logarc-ci:$1" bash -c '
      set -e
      mkdir -p /src && tar -x -C /src && cd /src
      # A repository, as actions/checkout leaves one: a test asks `git ls-files`.
      # Indexed before the ruleset link and the build; .gitignore keeps vendor/
      # and the sidecar out of it either way.
      git init -q && git add -A
      mkdir -p vendor && ln -s /ruleset vendor/coreruleset
      uv pip install -q -e ".[dev,gui]"
      '"$2"
}

lint_and_types() {
  local log=$RUN/lint-typecheck.log
  { image "$LINT_PY" && in_container "$LINT_PY" '
      ruff check .
      ruff format --check .
      mypy src/logarc
      mypy --platform win32 src/logarc'; } > "$log" 2>&1
  record lint-typecheck $?
}

linux_tests() {  # linux_tests <python version>
  local log=$RUN/linux-$1.log
  { image "$1" && in_container "$1" '
      (cd crs && go build -o crs-sidecar .)
      python -c "import sys; print(\"python\", sys.version.split()[0])"
      pytest -p no:cacheprovider --ignore=tests/gui -n 4 \
        --cov=logarc --cov-report=term-missing --cov-fail-under=0
      run() { QT_QPA_PLATFORM=offscreen pytest -p no:cacheprovider tests/gui --cov=logarc --cov-append --cov-report=term-missing; }
      set +e
      run; code=$?
      if [ "$code" -eq 139 ]; then echo "WARNING: GUI suite segfaulted (known intermittent); running it once more"; run; code=$?; fi
      exit $code'; } > "$log" 2>&1
  record "linux-$1" $?
}

linux_side() {
  if [ "$HAVE_DOCKER" = 0 ]; then
    record lint-typecheck skip
    for py in $PYTHONS; do record "linux-$py" skip; done
    return
  fi
  lint_and_types
  for py in $PYTHONS; do linux_tests "$py"; done
}

# -- Windows: tests, natively, in a throwaway worktree ------------------------------
WT=$CI_DIR/wt

# The worktree's ruleset is a junction to the real clone. Deleting the worktree
# with `rm -rf` or `git worktree remove` could follow it and empty the clone, so
# the junction is unlinked first, with `rmdir`, which removes only the link.
drop_worktree() {
  if [ -e "$WT/vendor/coreruleset" ]; then
    MSYS_NO_PATHCONV=1 cmd /c rmdir "$(cygpath -w "$WT/vendor/coreruleset")"
  fi
  git -C "$REPO" worktree remove --force "$WT" >/dev/null 2>&1
  rm -rf "$WT"
  if [ "$(ls "$RULESET/rules" 2>/dev/null | wc -l)" != "$RULES_BEFORE" ]; then
    echo "!! vendor/coreruleset/rules changed during the run"; exit 3
  fi
}

windows_tests() {  # windows_tests <python version>
  local py=$1 venv=$CI_DIR/venv-$1 log=$RUN/windows-$1.log
  {
    # Fresh every run, as a runner's is: uv-managed Python, and the project
    # installed from the commit under test into an empty environment, so a
    # dependency pyproject.toml forgot fails here as it would there.
    "$UV" venv --clear --managed-python --python "$py" "$(cygpath -w "$venv")" &&
    "$UV" pip install --python "$(cygpath -w "$venv/Scripts/python.exe")" -e "$(cygpath -w "$WT")[dev,gui]" &&
    cd "$WT" &&
    export PYTEST_DEBUG_TEMPROOT="$(cygpath -w "$TEMPROOT")" LOGARC_REQUIRE_CRS=1 &&
    rm -f .coverage &&
    "$venv/Scripts/python.exe" -m pytest -p no:cacheprovider --ignore=tests/gui -n 4 \
      --cov=logarc --cov-report=term-missing --cov-fail-under=0 &&
    QT_QPA_PLATFORM=offscreen "$venv/Scripts/python.exe" -m pytest -p no:cacheprovider tests/gui \
      --cov=logarc --cov-append --cov-report=term-missing
  } > "$log" 2>&1
  record "windows-$py" $?
}

windows_side() {
  if [ "$WINDOWS" = 0 ]; then
    for py in $PYTHONS; do record "windows-$py" skip; done
    return
  fi
  drop_worktree
  git worktree add --detach "$WT" "$SHA" >/dev/null || { for py in $PYTHONS; do record "windows-$py" 2; done; return; }
  mkdir -p "$WT/vendor"
  # A junction, made by PowerShell: through Git Bash, `cmd //c mklink /J` had
  # its switch mangled and failed with nothing but a line on stderr.
  powershell.exe -NoProfile -Command "New-Item -ItemType Junction -Path '$(cygpath -w "$WT/vendor/coreruleset")' -Target '$(cygpath -w "$RULESET")' | Out-Null"
  if [ ! -d "$WT/vendor/coreruleset/rules" ] ||
     ! (cd "$WT/crs" && "$GO" build -o crs-sidecar.exe .) > "$RUN/sidecar-windows.log" 2>&1; then
    for py in $PYTHONS; do record "windows-$py" 2; done; return
  fi
  for py in $PYTHONS; do windows_tests "$py"; done
}

# Linux beside Windows: different machines in CI, here mostly Docker waiting.
linux_side &
LINUX=$!
windows_side
wait "$LINUX"
[ "$WINDOWS" = 1 ] && drop_worktree

# -- summary --------------------------------------------------------------------
JOBS="lint-typecheck"
for py in $PYTHONS; do JOBS="$JOBS windows-$py"; done
for py in $PYTHONS; do JOBS="$JOBS linux-$py"; done
status=0
{
  echo "local CI: $REF @ $SHORT  ($(date '+%Y-%m-%d %H:%M'))"
  for job in $JOBS; do
    code=$(cat "$RUN/$job.exit" 2>/dev/null || echo "?")
    case "$code" in
      0) verdict=PASS ;;
      skip) verdict="SKIP" ;;
      *) verdict="FAIL ($code)" ;;
    esac
    counts=$(grep -E "^=+ .*(passed|failed|error)" "$RUN/$job.log" 2>/dev/null | sed 's/=//g; s/^ *//; s/ *$//' | tr '\n' ';')
    cover=$(grep -E "^TOTAL" "$RUN/$job.log" 2>/dev/null | tail -1 | awk '{print $NF}')
    printf '  %-15s %-10s %s %s\n' "$job" "$verdict" "${counts:-}" "${cover:+coverage $cover}"
  done
} | tee "$RUN/SUMMARY.txt"
grep -q "FAIL" "$RUN/SUMMARY.txt" && status=1
[ "$status" = 0 ] && grep -q "SKIP" "$RUN/SUMMARY.txt" && status=3
exit "$status"
