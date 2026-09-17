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
from pathlib import Path

from logarc.detect.rules import load_rules

ROOT = Path(__file__).parent.parent

# --------------------------------------------------------------------------
# The pinned CRS revision

#: Every file that names it. Kept by hand so the second test can fail when the
#: list and the tree disagree.
NAMES_THE_PIN = (
    ".github/workflows/ci.yml",
    "README.md",
    "crs/README.md",
    "docs/evaluation.md",
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
