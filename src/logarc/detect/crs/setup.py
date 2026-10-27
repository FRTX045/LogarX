"""Getting CRS working in a source checkout: once, on purpose, `logarc-dev setup-crs`.

The packaged Windows application carries the sidecar and the ruleset, so it has
nothing to set up. A source checkout has neither: the ruleset is a git clone
this repository does not vendor, and the sidecar is a Go program to build. Until
this existed the reader was handed two commands, and the clone one fetched CRS's
newest rules rather than the revision every figure here was measured against.

**It reaches for the network only because it was asked to.** Fetching the
ruleset on first use would have been quieter, and the tool promises no network,
so it does not. This command says what it needs — git, Go and a connection,
once — and finishes by replaying a known payload, because fetched and built is
not the same as working.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs.sidecar import SidecarConfig, _install_root, binary_name, run_sidecar

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["CRS_REPOSITORY", "CRS_REVISION", "SetupError", "binary_name", "setup_crs"]

#: The ruleset revision this project measures against. `.github/workflows/ci.yml`
#: is the source of truth; `tests/test_documented_figures.py` fails if the two
#: ever name different revisions.
CRS_REVISION: Final = "d694d465951ee06347214f1291ae096e40700001"

CRS_REPOSITORY: Final = "https://github.com/coreruleset/coreruleset.git"

#: A payload every CRS revision at paranoia level 1 reports, sent to prove the
#: sidecar and the ruleset work together rather than merely exist.
_CHECK_QUERY: Final = "id=1' UNION SELECT password FROM users--"


class SetupError(RuntimeError):
    """CRS could not be set up, and the message says what to do instead."""


def setup_crs(
    root: Path | None = None,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    verify: Callable[[], None] | None = None,
) -> list[str]:
    """Fetch the pinned ruleset and build the sidecar where a checkout keeps them.

    Returns what was done, one line per step. Anything already in place is left
    alone. Raises `SetupError` with the remedy when a tool is missing or a step
    fails; nothing is half-done by a missing tool, because both are looked for
    before anything is changed.
    """
    if getattr(sys, "frozen", False):
        return ["The packaged application already carries CRS: there is nothing to set up."]

    root = root or _install_root()
    ruleset = root / "vendor" / "coreruleset"
    crs_dir = root / "crs"
    binary = crs_dir / binary_name()

    git = which("git")
    if git is None:
        raise SetupError(
            "git is not installed, and it is how the CRS ruleset is fetched. Install it from "
            "git-scm.com, or use the packaged application, which already carries CRS."
        )
    needs_build = _stale(binary, crs_dir)
    go = which("go") if needs_build else None
    if needs_build and go is None:
        raise SetupError(
            "Go is not installed, and the CRS sidecar is a Go program. Install Go 1.25 or "
            "newer from go.dev and run this again, or use the packaged application, which "
            "already carries CRS."
        )

    said = [_ruleset(ruleset, git, run)]
    if go is not None:
        _call(run, [go, "build", "-trimpath", "-o", binary.name, "."], cwd=crs_dir)
        said.append(f"Sidecar: built {binary}")
    else:
        said.append(f"Sidecar: up to date at {binary}")

    (verify or (lambda: _verify(binary, ruleset, crs_dir)))()
    said.append("Checked: CRS caught a test SQL injection, so enrichment will work.")
    return said


def _ruleset(ruleset: Path, git: str, run: Callable[..., subprocess.CompletedProcess[str]]) -> str:
    pin = CRS_REVISION[:8]
    has_rules = any((ruleset / "rules").glob("REQUEST-*.conf"))
    if not ruleset.exists() or not any(ruleset.iterdir()):
        _call(
            run, [git, "clone", "--filter=blob:none", "--no-checkout", CRS_REPOSITORY, str(ruleset)]
        )
        _call(run, [git, "-C", str(ruleset), "checkout", "--detach", CRS_REVISION])
        return f"Ruleset: fetched CRS at {pin} into {ruleset}"
    if not has_rules and not (ruleset / ".git").exists():
        raise SetupError(
            f"{ruleset} exists and is not a CRS checkout, so it was left alone. Move it "
            "aside and run this again."
        )
    head = run(
        [git, "-C", str(ruleset), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if head.returncode != 0:
        return f"Ruleset: present at {ruleset}; not a git checkout, so its revision is unknown"
    if head.stdout.strip() == CRS_REVISION:
        return f"Ruleset: already at {pin}"
    _call(run, [git, "-C", str(ruleset), "fetch", "--filter=blob:none", "origin", CRS_REVISION])
    _call(run, [git, "-C", str(ruleset), "checkout", "--detach", CRS_REVISION])
    return f"Ruleset: moved to {pin}, the revision this project measures against"


def _stale(binary: Path, crs_dir: Path) -> bool:
    """Whether the sidecar is missing or older than any of its source."""
    if not binary.exists():
        return True
    sources = [*crs_dir.glob("*.go"), crs_dir / "go.mod", crs_dir / "go.sum"]
    newest = max((path.stat().st_mtime for path in sources if path.exists()), default=0.0)
    return binary.stat().st_mtime < newest


def _call(
    run: Callable[..., subprocess.CompletedProcess[str]],
    command: list[str],
    *,
    cwd: Path | None = None,
) -> None:
    result = run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SetupError(f"{' '.join(command[:3])} failed:\n{(result.stderr or '').strip()}")


def _verify(binary: Path, ruleset: Path, crs_dir: Path) -> None:
    probe = NormalizedEvent(
        timestamp=datetime.now(UTC),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("setup-crs", 1),
        method="GET",
        path="/",
        query=_CHECK_QUERY,
        protocol="HTTP/1.1",
        status=200,
        user_agent="logarc-dev setup-crs",
    )
    config = SidecarConfig(binary=binary, rules=ruleset, conf=crs_dir)
    found = run_sidecar([probe], config=config, workers=1)
    if not any(item.attack_family == "attack-sqli" for item in found):
        raise SetupError(
            "CRS ran but did not catch the test payload, so something about this setup is "
            "wrong. crs/README.md has the manual steps to compare against."
        )
