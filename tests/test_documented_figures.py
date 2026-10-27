"""Figures the documentation states about the tree, checked against the tree.

Two kinds of claim live in `docs/` and the READMEs: measurements, which belong to
bytes and are pinned by checksum elsewhere, and *figures about this repository* —
the pinned CRS revision, how many rules there are. The second kind goes stale
silently, because nothing recomputes it when the thing it describes changes.

Both were wrong or unguarded when this file was written. `.github/workflows/
ci.yml` claimed the CRS revision was "stated once here" and so could not drift;
it is stated in five places and nothing compared them. `docs/evaluation.md` said
the tree held 67 rules, and it held 71.

A figure earns its place in the documentation only when something fails when it
is wrong.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

from logarc.detect.rules import load_rules

ROOT = Path(__file__).parent.parent

# --------------------------------------------------------------------------
# The pinned CRS revision

#: Every file that names it. Kept by hand so the second test can fail when the
#: list and the tree disagree.
NAMES_THE_PIN = (
    ".github/workflows/ci.yml",
    "crs/README.md",
    "docs/evaluation.md",
    "docs/evaluations/exploit-evidence-first-validation.md",
    "docs/evaluations/ip-prioritization-validation.md",
    "docs/evaluations/suspicious-recommendations-validation.md",
    "docs/installing.md",
    "docs/ip-prioritization.md",
    "src/logarc/detect/crs/setup.py",
)

SHA1 = re.compile(r"\b[0-9a-f]{40}\b")
TEXT = {".md", ".yml", ".yaml", ".py", ".go", ".toml", ".txt", ".cfg", ".ini"}


def pinned_in_ci() -> str:
    lines = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8").splitlines()
    line = next(one for one in lines if one.strip().startswith("CRS_COMMIT:"))
    return line.split(":", 1)[1].strip()


def test_every_file_naming_the_crs_revision_names_the_same_one() -> None:
    expected = pinned_in_ci()

    for name in NAMES_THE_PIN:
        found = set(SHA1.findall((ROOT / name).read_text(encoding="utf-8")))
        assert found == {expected}, f"{name} names {sorted(found)}; CI pins {expected}"


def test_no_tracked_file_names_the_pin_without_being_listed() -> None:
    expected = pinned_in_ci()
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()

    naming = {
        name
        for name in tracked
        if Path(name).suffix in TEXT
        and expected in (ROOT / name).read_text(encoding="utf-8", errors="replace")
    }

    assert naming == set(NAMES_THE_PIN)


# --------------------------------------------------------------------------
# How many rules the tree holds

#: Each entry is a sentence in the documentation that states the live rule count,
#: and the pattern that finds the number in it. Anchored to the wording on
#: purpose: rewording one of these is exactly when its figure is most likely to
#: be left behind, and a failure here says which sentence to look at.
STATES_THE_RULE_COUNT = (
    ("docs/evaluation.md", r"tree now holds (\d+) rules"),
    ("samples/README.md", r"reaches all (\d+) detection rules"),
    ("samples/demo/README.md", r"Detection rules exercised \| \*\*(\d+) of (\d+)\*\*"),
    ("samples/demo/README.md", r"It is (\d+) of (\d+) today"),
)


def test_the_documented_rule_count_is_the_real_one() -> None:
    live = len(load_rules([ROOT / "src" / "logarc" / "detect" / "rulepacks"]))

    for name, pattern in STATES_THE_RULE_COUNT:
        text = (ROOT / name).read_text(encoding="utf-8")
        found = re.search(pattern, text)
        assert found, f"{name}: no sentence matched /{pattern}/ — reworded? update this test"
        for stated in found.groups():
            assert int(stated) == live, (
                f"{name} states {stated} rules near '{found.group(0)}'; the tree holds {live}"
            )


# --------------------------------------------------------------------------
# The coverage floor


def test_the_floor_ci_prints_is_the_floor_that_is_enforced() -> None:
    # pyproject's fail_under is what can fail a build. ci.yml writes the floor
    # into the job summary as a literal, which is where a reader actually looks,
    # so the two disagreeing means the summary quietly misreports the standard.
    enforced = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    floor = enforced["tool"]["coverage"]["report"]["fail_under"]

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    printed = re.search(r"floor is (\d+)%", workflow)

    assert printed, "ci.yml no longer prints the floor — reworded? update this test"
    assert int(printed.group(1)) == floor, (
        f"ci.yml prints a floor of {printed.group(1)}%; pyproject enforces {floor}%"
    )


# --------------------------------------------------------------------------
# How big the demo log is

#: The line count is stated in prose in two places. It cannot drift unnoticed on
#: its own — SHA256SUMS pins the bytes — but regenerating the log makes that
#: test fail, and the fix for *it* is to rewrite the digest, which leaves these
#: sentences behind. This is the gap between the two.
STATES_THE_DEMO_SIZE = (
    ("samples/README.md", r"It is (\d+) lines and reaches"),
    ("samples/demo/README.md", r"It is (\d+) lines of three days"),
    ("samples/demo/README.md", r"Lines / events / quarantined \| (\d+) /"),
)


def test_the_documented_demo_log_size_is_the_real_one() -> None:
    lines = len((ROOT / "samples/demo/demo.log").read_bytes().decode("utf-8").splitlines())

    for name, pattern in STATES_THE_DEMO_SIZE:
        text = (ROOT / name).read_text(encoding="utf-8")
        found = re.search(pattern, text)
        assert found, f"{name}: no sentence matched /{pattern}/ — reworded? update this test"
        assert int(found.group(1)) == lines, (
            f"{name} states {found.group(1)} lines near '{found.group(0)}'; the log has {lines}"
        )


# --------------------------------------------------------------------------
# The excerpt figures a reader can rerun

#: The sentence in the README quoting the committed excerpt's CRS scores.
EXCERPT_SENTENCE = (
    r"committed ([\d,]+)-request excerpt.*?accuracy ([\d.]+), macro F1 ([\d.]+) and "
    r"(\d+) false alarms with CRS, (\d+) attack requests\s+missed"
)


def test_the_readme_quotes_the_excerpt_scores_that_are_committed() -> None:
    """Offered as the figures anyone can rerun, so they have to be the ones the
    suite reruns."""
    import json

    scores = json.loads(
        (ROOT / "tests/data/apache-shopfront/excerpt.scores.crs.json").read_text(encoding="utf-8")
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    found = re.search(EXCERPT_SENTENCE, readme, re.DOTALL)
    assert found, f"README.md: no sentence matched /{EXCERPT_SENTENCE}/; reworded? update this test"

    requests, accuracy, macro_f1, false_alarms, missed = found.groups()
    assert int(requests.replace(",", "")) == scores["binary"]["total"]
    assert accuracy == f"{scores['classification']['accuracy']:.4f}"
    assert macro_f1 == f"{scores['classification']['macro_f1']:.4f}"
    assert int(false_alarms) == scores["binary"]["false_positives"]
    assert int(missed) == scores["binary"]["false_negatives"]
