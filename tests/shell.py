"""A shell for the tests that run this repository's shell scripts."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest


def bash() -> str:
    """A bash that can run a script by its repository path.

    On Windows that means Git Bash. `bash` on PATH can be WSL's launcher in
    System32, which runs inside Linux and cannot open this checkout's paths.
    """
    if os.name == "nt":
        git_bash = (
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
        )
        if git_bash.exists():
            return str(git_bash)
        found = shutil.which("bash")
        if found and "system32" not in found.lower():
            return found
        pytest.skip("Git Bash is not installed")
    found = shutil.which("bash")
    if found is None:
        pytest.skip("bash is not installed")
    return found
