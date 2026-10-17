#!/usr/bin/env bash
# Rewrite tests/data/crs-corpus-detections.json from a complete CRS clone.
#
#   tools/regen-crs-corpus.sh [<git ref>]   for a commit (default: HEAD)
#   tools/regen-crs-corpus.sh --print-pin   show what was read from the workflow
#
# The record is what the CRS sidecar reports for every request in CRS's
# regression corpus (tests/detect/crs/test_corpus_detections.py), and it must
# come from the whole corpus. On Windows a virus scanner removes some of the
# corpus files, PHP and web-shell samples, from the checkout. So this replays it
# in a Linux container, from a fresh clone at the commit CI pins, and copies
# only the record back. The generator refuses a corpus missing any file, so a
# damaged clone cannot be recorded from here either.
#
# It records the commit, not your working tree. Read the per-rule diff before
# committing what it writes: a changed count is a changed detection.
#
# Needs git and Docker. Uses the image tools/local-ci.sh builds, and the same
# caches.
set -euo pipefail

REPO=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
WORKFLOW=$REPO/.github/workflows/ci.yml
RECORD=tests/data/crs-corpus-detections.json

PY=$(grep -m1 'python-version: "' "$WORKFLOW" | sed 's/.*"\(.*\)".*/\1/')
CRS_COMMIT=$(grep -m1 'CRS_COMMIT:' "$WORKFLOW" | awk '{print $2}')
if [ -z "$PY" ] || [ -z "$CRS_COMMIT" ]; then
  echo "could not read the Python version and the CRS pin from $WORKFLOW"; exit 2
fi
if [ "${1:-}" = "--print-pin" ]; then
  echo "python: $PY"
  echo "crs: $CRS_COMMIT"
  exit 0
fi

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac
winpath() { if [ "$WINDOWS" = 1 ]; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

SHA=$(git -C "$REPO" rev-parse --verify "${1:-HEAD}^{commit}")
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
echo "recording $RECORD for ${SHA:0:7} against CRS ${CRS_COMMIT:0:7}"

MSYS_NO_PATHCONV=1 docker build -q -t "logarc-ci:$PY" --build-arg "PY=$PY" \
  -f "$(winpath "$REPO/tools/local-ci.Dockerfile")" "$(winpath "$REPO/tools")" > /dev/null

git -C "$REPO" archive "$SHA" | MSYS_NO_PATHCONV=1 docker run -i --rm \
  -v "$(winpath "$OUT"):/out" \
  -v logarc-ci-uv:/root/.cache/uv -v logarc-ci-go:/root/go \
  -e CRS_COMMIT="$CRS_COMMIT" "logarc-ci:$PY" bash -c '
    set -e
    mkdir -p /src && tar -x -C /src && cd /src
    git init -q && git add -A
    git clone -q --filter=blob:none --no-checkout \
      https://github.com/coreruleset/coreruleset.git vendor/coreruleset
    git -C vendor/coreruleset checkout -q --detach "$CRS_COMMIT"
    echo "corpus files: $(find vendor/coreruleset/tests/regression/tests -name "*.yaml" | wc -l)"
    (cd crs && go build -o crs-sidecar . && go version -m crs-sidecar | grep go-re2 || true)
    uv pip install -q -e ".[dev]"
    python tests/detect/crs/test_corpus_detections.py
    LOGARC_REQUIRE_CRS=1 python -m pytest -q -p no:cacheprovider --no-cov \
      tests/detect/crs/test_corpus_detections.py
    cp tests/data/crs-corpus-detections.json /out/
  '

cp "$OUT/crs-corpus-detections.json" "$REPO/$RECORD"
echo "written: $RECORD"
git -C "$REPO" diff --stat -- "$RECORD"
