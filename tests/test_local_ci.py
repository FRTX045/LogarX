"""`tools/local-ci.sh` runs the jobs of `.github/workflows/ci.yml` on a developer's machine.

It is the merge gate while the hosted runners cannot be used, and the two must
not drift: a Python version added to the workflow and not to the script would
leave every merge untested on it, with every summary still reading PASS. So the
script reads its matrix and the CRS pin out of the workflow rather than
repeating them, and these tests hold that in place by asking the script what it
read and comparing it with the workflow parsed independently.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from shell import bash

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = "tools/local-ci.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _printed_matrix() -> dict[str, str]:
    done = subprocess.run(
        [bash(), SCRIPT, "--print-matrix"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(line.split(": ", 1) for line in done.stdout.splitlines() if ": " in line)


def test_the_script_is_valid_bash() -> None:
    subprocess.run([bash(), "-n", SCRIPT], cwd=ROOT, check=True)


def test_the_python_versions_are_the_workflows() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    matrix = workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]

    assert _printed_matrix()["python"].split() == [str(version) for version in matrix]


def test_the_crs_pin_is_the_workflows() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    assert _printed_matrix()["crs"] == workflow["env"]["CRS_COMMIT"]


def test_lint_runs_on_the_python_the_workflow_lints_with() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    setup = next(step for step in workflow["jobs"]["lint"]["steps"] if "with" in step)

    assert _printed_matrix()["lint"] == str(setup["with"]["python-version"])
