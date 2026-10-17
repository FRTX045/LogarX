"""`tools/regen-crs-corpus.sh` rewrites the CRS corpus record from a complete clone.

The record must come from the ruleset CI tests against, or the next CI run
compares the sidecar with a corpus it was never recorded from. So the script
reads the pin out of the workflow rather than repeating it, and these tests ask
it what it read and compare that with the workflow parsed independently.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from shell import bash

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = "tools/regen-crs-corpus.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _printed_pin() -> dict[str, str]:
    done = subprocess.run(
        [bash(), SCRIPT, "--print-pin"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(line.split(": ", 1) for line in done.stdout.splitlines() if ": " in line)


def test_the_script_is_valid_bash() -> None:
    subprocess.run([bash(), "-n", SCRIPT], cwd=ROOT, check=True)


def test_the_crs_pin_is_the_workflows() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    assert _printed_pin()["crs"] == workflow["env"]["CRS_COMMIT"]


def test_it_runs_on_the_python_the_workflow_lints_with() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    setup = next(step for step in workflow["jobs"]["lint"]["steps"] if "with" in step)

    assert _printed_pin()["python"] == str(setup["with"]["python-version"])
