"""The demo log is the file its README says it is.

`samples/demo/README.md` prints a sha256 and a coverage figure, and neither was
checked by anything: editing the log without touching the README left both
quietly wrong, and a rule added to a pack the log cannot reach shipped green.
A digest nothing verifies is decoration, not provenance.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

DEMO = Path(__file__).parent.parent.parent / "samples" / "demo"


def recorded() -> dict[str, str]:
    return dict(
        line.split()[::-1]
        for line in (DEMO / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        if line.strip()
    )


def test_the_demo_log_matches_its_recorded_checksum() -> None:
    digests = recorded()

    assert set(digests) == {"demo.log"}
    for name, digest in digests.items():
        assert hashlib.sha256((DEMO / name).read_bytes()).hexdigest() == digest, name


def test_the_readme_quotes_the_recorded_checksum() -> None:
    # The README states the digest in prose as well, so the two can drift apart
    # even once SHA256SUMS is right. Every digest printed there must be one of
    # the recorded ones, and every recorded one must be printed.
    readme = (DEMO / "README.md").read_text(encoding="utf-8")

    assert set(re.findall(r"\b[0-9a-f]{64}\b", readme)) == set(recorded().values())


def test_every_rule_is_still_reachable_from_the_demo_log() -> None:
    # The command the README tells a maintainer to run, run the way they run it.
    # It is the gate behind "71 of 71", and until this test existed nothing
    # stood at it.
    check = subprocess.run(
        [sys.executable, str(DEMO / "make_demo.py"), "--check"],
        capture_output=True,
        text=True,
    )

    assert check.returncode == 0, check.stdout + check.stderr
