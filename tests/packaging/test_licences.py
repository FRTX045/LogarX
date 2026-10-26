"""The licences of what the Windows bundle ships.

`packaging/licences.py` works out which Python distributions and native
libraries PyInstaller actually collected, and places each one's licence files in
the bundle. The bundle is a redistribution of all of that code, Qt and CPython
and the libraries CPython links included, and their licences ask to travel with
it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    path = ROOT / "packaging" / "licences.py"
    spec = importlib.util.spec_from_file_location("logarc_licences_script", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def licences(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = _load()
    monkeypatch.setattr(module, "STAGE", tmp_path / "stage")
    return module


def _prefix(tmp_path: Path, packages: dict[str, list[str]]) -> Path:
    """An interpreter prefix laid out as conda leaves one: a licence at the root,
    a record per package naming its files, and the package cache's licences."""
    prefix = tmp_path / "prefix"
    (prefix / "conda-meta").mkdir(parents=True)
    (prefix / "LICENSE_PYTHON.txt").write_text("PSF\n", encoding="utf-8")
    for name, files in packages.items():
        extracted = prefix / "pkgs" / f"{name}-1.0-0"
        (extracted / "info" / "licenses").mkdir(parents=True)
        (extracted / "info" / "licenses" / "LICENSE").write_text(
            f"{name} terms\n", encoding="utf-8"
        )
        record = {"name": name, "files": files, "extracted_package_dir": str(extracted)}
        (prefix / "conda-meta" / f"{name}-1.0-0.json").write_text(json.dumps(record))
    return prefix


def test_collected_modules_are_named_by_their_top_level_package(licences: ModuleType) -> None:
    names = licences.top_levels(
        pure=["yaml.loader", "pydantic.main", "json.decoder"],
        binaries=["PyQt6/Qt6/bin/Qt6Core.dll", "PyQt6\\QtCore.pyd", "_duckdb.cp313-win_amd64.pyd"],
    )

    assert {"yaml", "pydantic", "json", "PyQt6", "_duckdb"} <= names


def test_a_module_is_credited_to_the_distribution_that_installed_it(
    licences: ModuleType,
) -> None:
    """The standard library belongs to no distribution and is covered by
    CPython's own licence instead."""
    assert set(licences.shipped({"yaml", "json"})) == {"pyyaml"}


def test_logarc_itself_is_left_to_the_licence_at_the_bundle_root(licences: ModuleType) -> None:
    assert "logarc" not in licences.shipped({"logarc", "yaml"})


def test_each_shipped_distribution_s_licences_go_in_a_folder_of_its_own(
    licences: ModuleType, tmp_path: Path
) -> None:
    entries = licences.datas(
        scripts=[], pure=["yaml.loader"], binaries=[], prefix=_prefix(tmp_path, {})
    )

    destinations = {dest for _source, dest in entries}
    assert "licenses/python/pyyaml" in destinations
    assert "licenses/python/python" in destinations, "CPython's own licence"
    assert all(Path(source).is_file() for source, _dest in entries)


def test_every_file_under_a_wheel_s_licences_folder_is_kept(licences: ModuleType) -> None:
    """Whatever it is called: a vendored component's notice is often named for
    the component, and a name filter dropped NumPy's `dragon4_LICENSE.txt`."""

    class Vendoring:
        files: ClassVar[list[Path]] = [
            Path("pkg-1.0.dist-info/licenses/LICENSE"),
            Path("pkg-1.0.dist-info/licenses/vendored/dragon4_LICENSE.txt"),
            Path("pkg-1.0.dist-info/METADATA"),
            Path("pkg-1.0.dist-info/COPYING"),
        ]

        def locate_file(self, path: Path) -> Path:
            return path

    kept = {inside.as_posix() for _source, inside in licences._licence_files(Vendoring())}

    assert kept == {"LICENSE", "vendored/dragon4_LICENSE.txt", "COPYING"}


def test_a_native_library_is_credited_to_the_conda_package_that_installed_it(
    licences: ModuleType, tmp_path: Path
) -> None:
    """libffi, expat and OpenSSL come with CPython but under licences of their
    own, and CPython's licence file does not carry them."""
    prefix = _prefix(tmp_path, {"libffi": ["Library/bin/ffi.dll"], "python": ["python313.dll"]})

    entries = licences.datas(
        scripts=[], pure=[], binaries=["ffi.dll", "python313.dll"], prefix=prefix
    )

    destinations = {dest for _source, dest in entries}
    assert {"licenses/native/libffi", "licenses/native/python"} <= destinations


def test_a_binary_nothing_accounts_for_stops_the_build(
    licences: ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(licences.LicenceError, match=r"mystery\.dll"):
        licences.datas(scripts=[], pure=[], binaries=["mystery.dll"], prefix=_prefix(tmp_path, {}))


def test_a_distribution_with_no_licence_file_stops_the_build(
    licences: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shipping it would ship code whose terms the bundle cannot show."""

    class Unlicensed:
        metadata: ClassVar[dict[str, str]] = {"Name": "no-licence"}
        files: ClassVar[list[Path]] = [Path("no_licence-1.0.dist-info/METADATA")]

        def locate_file(self, path: Path) -> Path:
            return path

    monkeypatch.setattr(licences, "shipped", lambda names: {"no-licence": Unlicensed()})

    with pytest.raises(licences.LicenceError, match="no-licence"):
        licences.datas(scripts=[], pure=["no_licence"], binaries=[], prefix=_prefix(tmp_path, {}))


def test_the_index_names_every_folder_the_bundle_should_hold(
    licences: ModuleType, tmp_path: Path
) -> None:
    prefix = _prefix(tmp_path, {"libffi": ["Library/bin/ffi.dll"]})

    entries = licences.datas(scripts=[], pure=["yaml.loader"], binaries=["ffi.dll"], prefix=prefix)

    (index,) = [source for source, dest in entries if Path(source).name == "INDEX.txt"]
    assert Path(index).read_text(encoding="utf-8").split() == [
        "python/python",
        "python/pyinstaller",
        "python/pyyaml",
        "native/libffi",
    ]


def test_the_crs_sidecar_is_left_to_the_licences_crs_bundle_collects(
    licences: ModuleType, tmp_path: Path
) -> None:
    """A Go binary, under licences `crs_bundle` gathers into
    `licenses/crs-sidecar`; no Python package or conda record owns it."""
    entries = licences.datas(
        scripts=[], pure=[], binaries=["crs\\crs-sidecar.exe"], prefix=_prefix(tmp_path, {})
    )

    assert not [dest for _source, dest in entries if "crs" in dest]


def test_pyinstaller_is_credited_for_the_bootloader_in_every_build(
    licences: ModuleType, tmp_path: Path
) -> None:
    """`logarc.exe` is PyInstaller's bootloader with the application appended,
    so every build ships PyInstaller code whatever else it collects."""
    entries = licences.datas(scripts=[], pure=[], binaries=[], prefix=_prefix(tmp_path, {}))

    assert "licenses/python/pyinstaller" in {dest for _source, dest in entries}


def test_a_runtime_hook_is_credited_to_the_package_it_came_from(licences: ModuleType) -> None:
    """Only a path under site-packages names a distribution: the bundle's own
    entry script sits in `packaging/`, which is also the name of an unrelated
    library on PyPI."""
    hook = "C:/venv/Lib/site-packages/PyInstaller/hooks/rthooks/pyi_rth_pyqt6.py"
    entry = "D:/proto2/packaging/logarc_gui.py"

    assert licences.script_owners([hook, entry]) == {"PyInstaller"}


def test_a_native_package_with_no_licence_in_its_cache_stops_the_build(
    licences: ModuleType, tmp_path: Path
) -> None:
    prefix = _prefix(tmp_path, {"libffi": ["Library/bin/ffi.dll"]})
    for path in (prefix / "pkgs").rglob("LICENSE"):
        path.unlink()

    with pytest.raises(licences.LicenceError, match="libffi"):
        licences.datas(scripts=[], pure=[], binaries=["ffi.dll"], prefix=prefix)


def test_a_runtime_hook_s_package_is_credited_in_the_bundle(
    licences: ModuleType, tmp_path: Path
) -> None:
    """A hook's package can reach the executable without a module or binary of
    its own being collected, and its notice has to come with it."""
    hook = "C:/venv/Lib/site-packages/yaml/rthook.py"

    entries = licences.datas(scripts=[hook], pure=[], binaries=[], prefix=_prefix(tmp_path, {}))

    assert "licenses/python/pyyaml" in {dest for _source, dest in entries}
