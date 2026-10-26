"""The licences of the Python packages and native libraries the bundle ships.

The bundle is a redistribution of everything PyInstaller collected into it, Qt
and CPython and the native libraries CPython links included, and most of their
licences ask to travel with the code. Which those are is read from what the
build actually collected, not from the dependency list: the command line and its
libraries are kept out of the bundle on purpose, and a notice for code that is
not shipped claims something the bundle does not contain.

Used from `packaging/logarc.spec` once `Analysis` has run:

    for source, dest in datas(scripts=..., pure=..., binaries=...): ...

Each collected module is credited to the installed distribution that provides
it, and each collected binary no distribution owns to the conda package that
installed it, whose licence conda keeps in its package cache. `datas()` raises
rather than returning a short list, so anything shipped without a licence to go
with it stops the build. It also writes `INDEX.txt`, the notice folders the
bundle should hold, which `packaging/rebuild.py` checks the finished bundle
against.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]

#: Where the generated index is written before the spec bundles it.
STAGE: Final = ROOT / "build" / "licences"

#: Where the notices go in the bundle, beside `licenses/crs-sidecar`.
DEST: Final = "licenses"
INDEX: Final = "INDEX.txt"

#: Its own licence and notice are at the bundle root already.
_OWN: Final = "logarc"

#: `logarc.exe` is PyInstaller's bootloader with the application appended, so
#: every build ships PyInstaller code, whatever else it collects.
_BOOTLOADER: Final = "PyInstaller"

#: Bundle folders whose licences are collected elsewhere: the CRS sidecar's,
#: which `crs_bundle` gathers into `licenses/crs-sidecar`.
_ELSEWHERE: Final = frozenset({"crs"})

#: Licence files that sit loose in a dist-info rather than under `licenses/`.
_NOTICE: Final = re.compile(r"(?i)^(licen[cs]e|copying|copyright|notice|authors)")

#: Where CPython keeps its licence: python.org installs and conda name it differently.
_PYTHON_LICENCES: Final = ("LICENSE.txt", "LICENSE_PYTHON.txt", "LICENSE")


class LicenceError(RuntimeError):
    """Something the bundle ships has no licence file to ship beside it."""


def top_levels(*, pure: Iterable[str], binaries: Iterable[str]) -> set[str]:
    """The top-level import names behind PyInstaller's collected modules and
    binaries: `yaml` for `yaml.loader`, `PyQt6` for `PyQt6/Qt6/bin/Qt6Core.dll`,
    `_duckdb` for `_duckdb.cp313-win_amd64.pyd`."""
    return {name.split(".", 1)[0] for name in pure} | {_top(dest) for dest in binaries}


def _top(dest: str) -> str:
    return re.split(r"[\\/]", dest, maxsplit=1)[0].split(".", 1)[0]


def script_owners(scripts: Iterable[str]) -> set[str]:
    """The top-level packages the runtime hooks PyInstaller put in the executable
    came from: `PyInstaller` for `.../site-packages/PyInstaller/hooks/rthooks/x.py`.

    Only a path under `site-packages` names a package. The bundle's own entry
    script sits in `packaging/`, which is also the name of an unrelated library.
    """
    owners = set()
    for script in scripts:
        parts = PurePosixPath(script.replace("\\", "/")).parts
        lowered = [part.lower() for part in parts]
        if "site-packages" in lowered:
            after = lowered.index("site-packages") + 1
            if after < len(parts) - 1:
                owners.add(parts[after])
    return owners


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def shipped(names: Iterable[str]) -> dict[str, metadata.Distribution]:
    """The installed distributions that provide `names`, by canonical name.

    A name no distribution owns is the standard library, which CPython's own
    licence covers, a native library, which `native()` accounts for, or the
    bundle's own entry script.
    """
    owners = metadata.packages_distributions()
    found: dict[str, metadata.Distribution] = {}
    for name in names:
        for owner in owners.get(name, ()):
            distribution = metadata.distribution(owner)
            key = _canonical(distribution.metadata["Name"])
            if key != _OWN:
                found[key] = distribution
    return found


def _licence_files(distribution: metadata.Distribution) -> list[tuple[Path, PurePosixPath]]:
    """Each licence file in the distribution's dist-info, with where it sits
    inside its `licenses/` folder, so two files of one name do not collide.

    Everything under `licenses/` counts whatever it is called: that folder is
    where a wheel puts its licence files, and a vendored component's notice is
    often named for the component (NumPy's `dragon4_LICENSE.txt`).
    """
    found = []
    for file in distribution.files or ():
        parts = PurePosixPath(str(file).replace("\\", "/")).parts
        if len(parts) < 2 or not parts[0].endswith(".dist-info"):
            continue
        if parts[1] == "licenses" and len(parts) > 2:
            inside = PurePosixPath(*parts[2:])
        elif len(parts) == 2 and _NOTICE.match(parts[1]):
            inside = PurePosixPath(parts[1])
        else:
            continue
        found.append((Path(distribution.locate_file(file)), inside))
    return found


def _python_licence(prefix: Path) -> Path:
    for name in _PYTHON_LICENCES:
        if (prefix / name).is_file():
            return prefix / name
    raise LicenceError(f"CPython's licence is not in {prefix}")


def _conda_owners(prefix: Path) -> dict[str, tuple[str, Path]]:
    """Each file conda installed under `prefix`, by lower-cased basename, with
    the package that installed it and where that package's licences are kept."""
    owners: dict[str, tuple[str, Path]] = {}
    for record in sorted((prefix / "conda-meta").glob("*.json")):
        data = json.loads(record.read_text(encoding="utf-8"))
        extracted = data.get("extracted_package_dir") or str(prefix / "pkgs" / record.stem)
        licences = Path(extracted) / "info" / "licenses"
        for file in data.get("files", ()):
            owners.setdefault(
                PurePosixPath(file.replace("\\", "/")).name.lower(), (data["name"], licences)
            )
    return owners


def native(binaries: Iterable[str], *, prefix: Path) -> tuple[dict[str, Path], list[str]]:
    """The conda packages behind each collected binary no Python distribution
    owns, with each one's licence folder, and the binaries nothing accounts for.

    CPython's own extension modules and DLLs come from conda's `python` package
    here, and the libraries they link (libffi, OpenSSL, expat and the rest) from
    packages of their own. Outside conda nothing records which package a DLL
    came from, so every such binary is reported unaccounted.
    """
    owned = metadata.packages_distributions()
    conda = _conda_owners(prefix)
    packages: dict[str, Path] = {}
    unaccounted = []
    for dest in binaries:
        if _top(dest) in owned or _top(dest) in _ELSEWHERE:
            continue
        name = PurePosixPath(dest.replace("\\", "/")).name.lower()
        if name in conda:
            package, licences = conda[name]
            packages[package] = licences
        else:
            unaccounted.append(dest)
    return packages, sorted(unaccounted)


def datas(
    *,
    scripts: Iterable[str],
    pure: Iterable[str],
    binaries: Iterable[str],
    prefix: Path | None = None,
) -> list[tuple[str, str]]:
    """`(source file, bundle folder)` for every licence the bundle has to carry.

    Raises `LicenceError` naming each shipped package with no licence file and
    each binary nothing accounts for.
    """
    prefix = prefix or Path(sys.base_prefix)
    binaries = list(binaries)
    entries = [(str(_python_licence(prefix)), f"{DEST}/python/python")]
    folders = ["python/python"]
    problems = []

    names = top_levels(pure=pure, binaries=binaries) | script_owners(scripts) | {_BOOTLOADER}
    for key, distribution in sorted(shipped(names).items()):
        files = _licence_files(distribution)
        if not files:
            problems.append(f"{key} (no licence file in its dist-info)")
        for source, inside in files:
            entries.append(
                (str(source), (PurePosixPath(DEST, "python", key) / inside.parent).as_posix())
            )
        folders.append(f"python/{key}")

    packages, unaccounted = native(binaries, prefix=prefix)
    for package, licences in sorted(packages.items()):
        files = (
            sorted(path for path in licences.rglob("*") if path.is_file())
            if licences.is_dir()
            else []
        )
        if not files:
            problems.append(f"{package} (no licence in {licences})")
        for path in files:
            inside = path.parent.relative_to(licences)
            entries.append(
                (str(path), (PurePosixPath(DEST, "native", package) / inside.as_posix()).as_posix())
            )
        folders.append(f"native/{package}")
    problems.extend(f"{dest} (no package accounts for it)" for dest in unaccounted)

    if problems:
        raise LicenceError(
            "the bundle would ship these without a licence to go with them: " + "; ".join(problems)
        )
    STAGE.mkdir(parents=True, exist_ok=True)
    index = STAGE / INDEX
    index.write_text("".join(f"{folder}\n" for folder in folders), encoding="utf-8")
    entries.append((str(index), DEST))
    return entries
