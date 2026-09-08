"""Rebuild the packaged Windows bundle, but only from code that passes its tests.

Run it by hand at any time:

    .venv\\Scripts\\python.exe packaging\\rebuild.py

Prefer it to calling `pyinstaller` directly. The checks below are the reason it
exists, and a bundle that skips them is broken in ways that surface at runtime,
on someone else's machine, in the middle of a case.

**Building is the easy part.** Three things make a naive `pyinstaller` call the
wrong tool for this job:

* **PyInstaller exits 0 on a bundle missing what it could not see.** The rule
  packs are data; nothing imports them, so a freezer drops them without a word,
  and a build with no rules reports every request as benign — a failure that
  looks exactly like a clean log. The package metadata is where the case
  manifest gets `tool_version`; without it every case is stamped `0.0.0.dev0`.
  Both are handled in `packaging/logarc.spec`, and checked here in case that
  regresses, because the day the spec breaks is the day a build starts lying
  rather than the day it starts failing.

* **COLLECT deletes the old bundle first.** `INFO: Removing dir ...\\dist\\logarc`
  happens before the new one is written, so a build that fails after that point
  leaves no application at all. Everything is therefore built into a staging
  directory and swapped in only once it has passed.

* **A hook runs this after a merge.** Work arriving from someone else is exactly
  the work least likely to have been verified, so the tests run first and a red
  suite stops the build rather than packaging it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import traceback
from importlib import metadata
from pathlib import Path
from typing import Final

#: This file is `<root>/packaging/rebuild.py`. Derived from `__file__` rather
#: than the current directory, because a git hook runs this with whatever
#: directory the invoking client happened to have.
ROOT = Path(__file__).resolve().parents[1]
GIT_DIR = ROOT / ".git"

SPEC = ROOT / "packaging" / "logarc.spec"
DIST = ROOT / "dist"
LIVE = DIST / "logarc"
STAGING = DIST / ".staging"
PREVIOUS = DIST / ".previous"

#: PyInstaller's own work directory, and the half-built executable it leaves
#: there. `--distpath` moves the finished bundle; the work directory is not
#: `--distpath`'s to move, so this one stays behind after every build.
WORK = ROOT / "build" / "logarc"
INTERMEDIATE = WORK / "logarc.exe"
LOCK = DIST / ".rebuild.lock"
STATUS = DIST / "BUILD-STATUS.txt"
MARKER = GIT_DIR / "logarc-build-failed"

#: pytest's default temp root is unwritable on this machine.
TEMPROOT = Path(os.environ.get("LOCALAPPDATA", ROOT)) / "Temp" / "logarc-rebuild-pytest"

#: A stale lock should not block builds forever. Tests and build together take
#: about two minutes; anything holding it this long is a crash, not a live run.
LOCK_STALE_SECONDS = 30 * 60


def say(message: str) -> None:
    print(f"[rebuild] {message}", flush=True)


def head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()


def take_lock() -> bool:
    """One build at a time. Two PyInstaller runs share `build/`."""
    DIST.mkdir(parents=True, exist_ok=True)
    if LOCK.exists() and time.time() - LOCK.stat().st_mtime > LOCK_STALE_SECONDS:
        say(f"clearing a lock left behind over {LOCK_STALE_SECONDS // 60} minutes ago")
        LOCK.unlink(missing_ok=True)
    try:
        with LOCK.open("x", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
    except FileExistsError:
        return False
    return True


def fail(reason: str, detail: str = "") -> int:
    """Record the failure where it will be seen, and leave `dist/logarc` alone.

    The marker is what the git hooks print on the next command. A status file
    alone has to be opened to be read, which means a broken or stale bundle can
    sit there looking current — the same silent failure this script exists to
    catch in the bundle itself.
    """
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    say(f"STOPPED: {reason}")
    MARKER.write_text(f"{reason} (at {head()}, {stamp})\n", encoding="utf-8")
    STATUS.write_text(
        f"{stamp}  {head()}  NOT REBUILT\n  {reason}\n"
        + (f"\n{detail}\n" if detail else "")
        + "\nThe previously built application in dist/logarc is untouched and still runnable.\n",
        encoding="utf-8",
    )
    shutil.rmtree(STAGING, ignore_errors=True)
    return 1


def run_tests() -> tuple[bool, str]:
    """Red stops the build. `git pull` fires this hook too, and work arriving
    from someone else is the work least likely to have been verified."""
    say("running the test suite")
    TEMPROOT.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    result = subprocess.run(
        [str(ROOT / ".venv" / "Scripts" / "python.exe"), "-m", "pytest", "--no-cov", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTEST_DEBUG_TEMPROOT": str(TEMPROOT)},
    )
    elapsed = time.perf_counter() - started
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        failed = [line for line in output.splitlines() if line.startswith("FAILED")]
        say(f"tests failed after {elapsed:.0f}s")
        return False, "\n".join(failed[:20]) or output[-2000:]
    say(f"tests passed in {elapsed:.0f}s")
    return True, ""


def build() -> tuple[bool, str]:
    """Into staging, never over the live bundle."""
    pyinstaller = ROOT / ".venv" / "Scripts" / "pyinstaller.exe"
    if not pyinstaller.exists():
        found = shutil.which("pyinstaller")
        if not found:
            return False, 'pyinstaller not found - pip install -e ".[gui,package]"'
        pyinstaller = Path(found)

    shutil.rmtree(STAGING, ignore_errors=True)
    say("building into staging")
    started = time.perf_counter()
    result = subprocess.run(
        [
            str(pyinstaller),
            "--clean",
            "--noconfirm",
            "--distpath",
            str(STAGING),
            str(SPEC),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return False, ((result.stdout or "") + (result.stderr or ""))[-2000:]
    say(f"built in {time.perf_counter() - started:.0f}s")
    return True, ""


# -- the four checks PyInstaller's exit code cannot make ---------------------


def check_executable(bundle: Path) -> str | None:
    if not (bundle / "logarc.exe").exists():
        return "logarc.exe was not produced"
    return None


def check_rule_packs(bundle: Path) -> str | None:
    """Data files nothing imports. Missing means every request reads benign."""
    source = ROOT / "src" / "logarc" / "detect" / "rulepacks"
    packed = bundle / "_internal" / "logarc" / "detect" / "rulepacks"
    wanted = {path.name for path in source.glob("*.yaml")}
    if not wanted:
        return "no rule packs in the source tree to compare against"
    got = {path.name for path in packed.glob("*.yaml")} if packed.is_dir() else set()
    if missing := wanted - got:
        return f"rule packs missing from the bundle: {', '.join(sorted(missing))}"
    return None


def check_metadata(bundle: Path) -> str | None:
    """Where the case manifest gets the version it records."""
    found = list((bundle / "_internal").glob("logarc-*.dist-info/METADATA"))
    if not found:
        return "no logarc dist-info - every case would be stamped 0.0.0.dev0"
    match = re.search(
        r"^Version:\s*(.+)$",
        found[0].read_text(encoding="utf-8", errors="replace"),
        re.MULTILINE,
    )
    bundled = match.group(1).strip() if match else "?"
    try:
        expected = metadata.version("logarc")
    except metadata.PackageNotFoundError:
        return None
    if bundled != expected:
        return f"bundled version {bundled} does not match the source {expected}"
    return None


def check_no_browser_engine(bundle: Path) -> str | None:
    """ADR-0006: the canvas is QGraphicsView so no browser engine ships."""
    if intruders := list((bundle / "_internal").rglob("*QtWebEngine*")):
        return f"QtWebEngine is in the bundle ({len(intruders)} file(s)) - see ADR-0006"
    return None


def verify(bundle: Path) -> list[str]:
    checks = (check_executable, check_rule_packs, check_metadata, check_no_browser_engine)
    return [problem for check in checks if (problem := check(bundle)) is not None]


def running_instances() -> str:
    """Any `logarc.exe` currently running, as `tasklist` reports it.

    Asked only after a swap has already failed, and only so the failure can be
    worded correctly.

    The version this replaces asked the opposite question beforehand — can this
    executable be opened for writing — and reported "no" as "the packaged
    application is open". Wrong twice over. It ran immediately after PyInstaller
    finishes writing 243 MB, which is exactly when OneDrive and the virus
    scanner are holding that tree, and it asserted a cause it had never
    established: it fired with the application already closed and sent someone
    off to close it again. The lock was transient and gone a minute later.
    """
    try:
        listing = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq logarc.exe", "/NH"],
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return listing.strip() if "logarc.exe" in listing else ""


#: How long to keep trying the swap, in seconds between attempts. The tree
#: lives under OneDrive, and a freshly written 243 MB bundle is exactly what
#: OneDrive and the virus scanner are busiest with: the lock appears the moment
#: PyInstaller finishes and is gone a minute later. Waiting it out is the job.
_SWAP_WAITS: Final = (0.5, 1, 2, 4, 8, 16, 30, 30)


def _rename_insisting(source: Path, target: Path) -> None:
    """Rename, waiting out whatever is still holding the directory."""
    for wait in _SWAP_WAITS:
        try:
            source.rename(target)
            return
        except PermissionError:
            time.sleep(wait)
    source.rename(target)  # once more, and let this one raise


def swap(staged: Path) -> None:
    """Put the verified build in place, keeping the old one until it is.

    Rename-then-rename rather than delete-then-move, so there is no moment when
    `dist/logarc` is missing because a copy is halfway through — and if the
    second rename fails after the first succeeded, the old bundle goes back
    where it was. That window is short, but landing in it would leave no
    application at all, which is the one outcome this whole path exists to
    prevent.

    Once it holds, PyInstaller's intermediate executable goes too. That file
    has the application's name and icon and can never run: it looks beside
    itself for the `_internal` directory that only COLLECT writes, so opening
    it gives "Failed to load Python DLL" and nothing else. Leaving it in the
    tree means a search for `logarc.exe` answers with two indistinguishable
    hits, one of them broken by construction. Someone did open it.
    """
    shutil.rmtree(PREVIOUS, ignore_errors=True)
    displaced = False
    if LIVE.exists():
        _rename_insisting(LIVE, PREVIOUS)
        displaced = True
    try:
        _rename_insisting(staged, LIVE)
    except OSError:
        if displaced:
            PREVIOUS.rename(LIVE)
        raise
    shutil.rmtree(PREVIOUS, ignore_errors=True)
    shutil.rmtree(STAGING, ignore_errors=True)
    INTERMEDIATE.unlink(missing_ok=True)


def size_mb(path: Path) -> float:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) / (1024 * 1024)


def main() -> int:
    if not take_lock():
        say("another rebuild is already running - leaving it to finish")
        return 0
    try:
        return _rebuild()
    except Exception as exc:
        # Anything not anticipated above still has to be reported. Without this
        # an unexpected error escaped `main`, so no marker was written and
        # BUILD-STATUS.txt went on claiming the previous run's "ok" — a stale
        # bundle presenting itself as current, which is the exact silent
        # failure the checks below it exist to prevent.
        return fail(f"the rebuild crashed: {type(exc).__name__}: {exc}", traceback.format_exc())
    finally:
        LOCK.unlink(missing_ok=True)


def _rebuild() -> int:
    """Test, build, check, swap — stopping at the first thing that is wrong."""
    passed, detail = run_tests()
    if not passed:
        return fail("the test suite is red, so nothing was packaged", detail)

    built, detail = build()
    if not built:
        return fail("the build failed", detail)

    staged = STAGING / "logarc"
    if problems := verify(staged):
        return fail(
            "the build completed but is unusable: " + "; ".join(problems),
            "\n".join(f"  - {problem}" for problem in problems),
        )

    try:
        swap(staged)
    except OSError as exc:
        # Report what happened and name the causes without picking one. The
        # tree sits under OneDrive and gets read by the virus scanner, so the
        # lock is usually transient and already waited out above; a running
        # copy of the application holds it until someone closes that.
        running = running_instances()
        return fail(
            "the build is ready but could not be put in place",
            f"{exc}\n\n"
            + (
                f"logarc.exe is running:\n{running}\nClose it and run this again.\n"
                if running
                else "No logarc.exe is running, so something else is holding the\n"
                "folder — OneDrive finishing an upload, or the virus scanner\n"
                "reading 243 MB written seconds ago. Both let go shortly.\n"
            )
            + "\nRetry with:\n  .venv\\Scripts\\python.exe packaging\\rebuild.py\n\n"
            "The build passed every check; only the last step failed, and the\n"
            "application already in dist/logarc is untouched.",
        )

    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    say(f"verified and swapped in ({size_mb(LIVE):.0f} MB)")
    STATUS.write_text(
        f"{stamp}  {head()}  ok  {size_mb(LIVE):.0f} MB\n"
        "tests green; rule packs bundled; version metadata bundled; no QtWebEngine\n",
        encoding="utf-8",
    )
    MARKER.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
