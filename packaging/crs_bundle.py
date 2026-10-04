"""What the packaged application carries so that CRS works in it.

The sidecar is a Go program and the ruleset is a git clone; neither is Python,
so PyInstaller sees neither, and a build that left them out ran fine until
someone pressed the CRS button on another machine. Two halves, used by two
callers:

* `prepare()`, from `packaging/rebuild.py`: build the sidecar fresh from
  `crs/`, record the ruleset's revision, and gather the licences of everything
  compiled into the binary. A Go binary links its dependencies statically, so
  shipping it is shipping them, and their licences ask to travel with them.
* `datas()`, from `packaging/logarc.spec`: every file the bundle needs, mapped
  to the layout `logarc.detect.crs.sidecar` looks in when frozen. It refuses
  rather than returning a short list, so a spec run without `prepare()` fails at
  build time instead of producing an application with CRS quietly missing.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
CRS_DIR: Final = ROOT / "crs"
RULESET: Final = ROOT / "vendor" / "coreruleset"
NOTICE: Final = ROOT / "NOTICE"

#: Generated inputs to the bundle: the revision file and the licence tree.
#: Under `build/`, which is ignored, beside PyInstaller's own work directory.
STAGE: Final = ROOT / "build" / "crs-bundle"

#: Bundle paths. They mirror the source tree because the frozen application
#: resolves them the same way a checkout does, from a different root.
_CRS_DEST: Final = "crs"
_RULESET_DEST: Final = "vendor/coreruleset"
_LICENCES_DEST: Final = "licenses/crs-sidecar"

#: What counts as a licence notice in a Go module's root.
_NOTICE_PREFIXES: Final = ("LICENSE", "LICENCE", "COPYING", "NOTICE")


class CrsBundleError(RuntimeError):
    """Something the packaged CRS needs is missing or could not be made."""


def _binary_name() -> str:
    # The runtime's own definition, so the file bundled is the file it looks for.
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from logarc.detect.crs.sidecar import binary_name
    finally:
        sys.path.pop(0)
    return binary_name()


def _go() -> str:
    found = shutil.which("go")
    if found:
        return found
    default = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Go" / "bin" / "go.exe"
    if default.exists():
        return str(default)
    raise CrsBundleError("Go is not installed, so the CRS sidecar cannot be built")


def _run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode != 0:
        raise CrsBundleError(f"{' '.join(command[:3])} failed:\n{result.stderr.strip()}")
    return result.stdout


def _request_rules(ruleset: Path) -> list[Path]:
    return sorted((ruleset / "rules").glob("REQUEST-*.conf"))


def modules_from_go_list(output: str, *, main_dir: Path) -> list[tuple[str, Path]]:
    """Each dependency module once, from `go list -deps` lines of `path<TAB>dir`.

    The sidecar's own module is skipped: it is this project's code, covered by
    the project's LICENSE, which the bundle already carries.
    """
    seen: dict[str, Path] = {}
    for line in output.splitlines():
        path, _, directory = line.strip().partition("\t")
        if not path or not directory or Path(directory) == main_dir:
            continue
        seen.setdefault(path, Path(directory))
    return sorted(seen.items())


def copy_licences(modules: list[tuple[str, Path]], dest: Path) -> list[str]:
    """Copy each module's licence and notice files under its module path.

    Returns the modules that had none. A binary built from one of those is
    shipping code with no notice beside it, which is for a person to look at,
    not for this function to paper over.
    """
    unlicensed = []
    for module, source in modules:
        notices = [
            path
            for path in sorted(source.iterdir())
            if path.is_file() and path.name.upper().startswith(_NOTICE_PREFIXES)
        ]
        if not notices:
            unlicensed.append(module)
            continue
        target = dest / PurePosixPath(module)
        target.mkdir(parents=True, exist_ok=True)
        for path in notices:
            # Contents only. Go's module cache is read-only, and a copy that kept
            # the flag could not be deleted by the next build on Windows.
            shutil.copyfile(path, target / path.name)
    return unlicensed


def reset_stage(stage: Path) -> None:
    """Empty `stage`, including files an earlier build left read-only.

    Errors are not ignored: a stage that cannot be cleared must stop the build
    here, saying so, rather than surface a step later as a puzzling `mkdir`
    failure, which is how it first showed up.
    """
    if stage.exists():
        for path in stage.rglob("*"):
            if path.is_file():
                path.chmod(stat.S_IREAD | stat.S_IWRITE)
        shutil.rmtree(stage)
    stage.mkdir(parents=True)


def prepare(*, crs_dir: Path = CRS_DIR, ruleset: Path = RULESET, stage: Path = STAGE) -> list[str]:
    """Build the sidecar and stage what the bundle needs beside it.

    Built every time rather than reused, so the shipped binary is always the one
    `crs/main.go` describes now and never one compiled weeks ago. Returns the
    dependency modules that carried no licence file.
    """
    if not _request_rules(ruleset):
        raise CrsBundleError(
            f"the CRS ruleset is not at {ruleset} (no rules/REQUEST-*.conf); "
            "fetch it as crs/README.md describes"
        )
    go = _go()
    _run([go, "build", "-trimpath", "-o", _binary_name(), "."], crs_dir)

    reset_stage(stage)
    revision = _run(["git", "-C", str(ruleset), "rev-parse", "HEAD"], ROOT).strip()
    (stage / "REVISION").write_text(revision + "\n", encoding="utf-8")

    listing = _run(
        [go, "list", "-deps", "-f", "{{with .Module}}{{.Path}}\t{{.Dir}}{{end}}", "."], crs_dir
    )
    licences = stage / "licenses"
    unlicensed = copy_licences(modules_from_go_list(listing, main_dir=crs_dir), licences)
    # The standard library is compiled in as well, under Go's own licence.
    goroot = Path(_run([go, "env", "GOROOT"], crs_dir).strip())
    if (goroot / "LICENSE").exists():
        (licences / "go").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(goroot / "LICENSE", licences / "go" / "LICENSE")
    else:
        unlicensed.append("go (standard library)")
    return unlicensed


def datas(
    *,
    crs_dir: Path = CRS_DIR,
    ruleset: Path = RULESET,
    stage: Path = STAGE,
    notice: Path = NOTICE,
) -> list[tuple[str, str]]:
    """Every CRS file the bundle needs, as PyInstaller `(source, dest dir)` pairs.

    Only the request rules and their data files: the sidecar never loads
    RESPONSE-*.conf, because an access log carries no response body. And the
    project's NOTICE, which names the Apache-2.0 components and says it travels
    with any distribution containing a built sidecar — this one does.
    """
    binary = crs_dir / _binary_name()
    required = [
        binary,
        crs_dir / "coraza.conf",
        crs_dir / "crs-setup.conf",
        ruleset / "LICENSE",
        stage / "REVISION",
        notice,
    ]
    missing = [str(path) for path in required if not path.is_file()]
    rules = _request_rules(ruleset)
    if not rules:
        missing.append(f"{ruleset / 'rules'}/REQUEST-*.conf")
    if missing:
        raise CrsBundleError(
            "the packaged application would ship without working CRS; missing: "
            + ", ".join(missing)
            + ". packaging/rebuild.py prepares all of it."
        )

    pairs = [(str(path), _CRS_DEST) for path in required[:3]]
    pairs += [(str(ruleset / "LICENSE"), _RULESET_DEST), (str(stage / "REVISION"), _RULESET_DEST)]
    pairs += [(str(notice), ".")]
    pairs += [(str(path), f"{_RULESET_DEST}/rules") for path in rules]
    pairs += [
        (str(path), f"{_RULESET_DEST}/rules") for path in sorted((ruleset / "rules").glob("*.data"))
    ]
    licences = stage / "licenses"
    pairs += [
        (str(path), (PurePosixPath(_LICENCES_DEST) / path.parent.relative_to(licences)).as_posix())
        for path in sorted(licences.rglob("*"))
        if path.is_file()
    ]
    return pairs
