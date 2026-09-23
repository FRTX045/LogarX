"""The swap that puts a verified build in place.

`packaging/rebuild.py` is a script rather than part of the package, so it is
loaded here by path. It is worth testing anyway: it is the only thing standing
between a red suite and a broken `dist/logarc`, and it runs unattended from a
git hook where nobody reads its output.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _rebuild() -> ModuleType:
    """Load `packaging/rebuild.py` under a name that cannot shadow anything.

    Not `packaging.rebuild`: `packaging` is a real distribution on PyPI and is
    installed here, so importing that name would find the wrong thing.
    """
    path = ROOT / "packaging" / "rebuild.py"
    spec = importlib.util.spec_from_file_location("logarc_rebuild_script", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def rebuild() -> ModuleType:
    return _rebuild()


@pytest.fixture
def bundles(rebuild: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the script's fixed paths at a temporary tree."""
    dist = tmp_path / "dist"
    dist.mkdir()
    monkeypatch.setattr(rebuild, "LIVE", dist / "logarc")
    monkeypatch.setattr(rebuild, "PREVIOUS", dist / ".previous")
    monkeypatch.setattr(rebuild, "STAGING", dist / ".staging")
    monkeypatch.setattr(rebuild, "INTERMEDIATE", tmp_path / "build" / "logarc" / "logarc.exe")
    return tmp_path


def _staged(rebuild: ModuleType) -> Path:
    staged = rebuild.STAGING / "logarc"
    staged.mkdir(parents=True)
    (staged / "logarc.exe").write_bytes(b"the real one")
    return staged


def test_the_swap_puts_the_staged_bundle_where_the_application_lives(
    rebuild: ModuleType, bundles: Path
) -> None:
    rebuild.swap(_staged(rebuild))

    assert (rebuild.LIVE / "logarc.exe").read_bytes() == b"the real one"


def test_the_swap_discards_the_intermediate_executable(rebuild: ModuleType, bundles: Path) -> None:
    """The one in PyInstaller's work directory can never run, so it must not survive.

    It is a bootstrap loader with the same name and icon as the application and
    no `_internal` beside it, so double-clicking it produces "Failed to load
    Python DLL" and nothing else, forever. Leaving it in the tree means a search
    for `logarc.exe` returns two indistinguishable hits, one of which is broken
    by construction.
    """
    rebuild.INTERMEDIATE.parent.mkdir(parents=True)
    rebuild.INTERMEDIATE.write_bytes(b"bootstrap without its _internal")

    rebuild.swap(_staged(rebuild))

    assert not rebuild.INTERMEDIATE.exists()
    assert rebuild.INTERMEDIATE.parent.exists(), "only the executable goes, not the build cache"


def test_the_swap_does_not_mind_a_build_directory_that_was_never_written(
    rebuild: ModuleType, bundles: Path
) -> None:
    """A first build, or one run after `build/` was cleared by hand."""
    rebuild.swap(_staged(rebuild))

    assert (rebuild.LIVE / "logarc.exe").exists()


def test_the_swap_replaces_a_bundle_that_is_already_there(
    rebuild: ModuleType, bundles: Path
) -> None:
    rebuild.LIVE.mkdir(parents=True)
    (rebuild.LIVE / "logarc.exe").write_bytes(b"the old one")

    rebuild.swap(_staged(rebuild))

    assert (rebuild.LIVE / "logarc.exe").read_bytes() == b"the real one"
    assert not rebuild.PREVIOUS.exists(), "the displaced bundle is not kept once the swap holds"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native dependency selection")
def test_build_prefers_windows_system_dlls_to_unrelated_path_entries(
    rebuild: ModuleType, bundles: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from subprocess import CompletedProcess

    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("PATH", "C:\\unrelated-tools;C:\\Windows\\System32")
    monkeypatch.setattr(rebuild.shutil, "which", lambda name: "C:\\tools\\pyinstaller.exe")
    calls = []

    def run(args, **kwargs):
        calls.append(kwargs)
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(rebuild.subprocess, "run", run)
    assert rebuild.build()[0]
    assert calls[0]["env"]["PATH"].split(";")[0] == "C:\\Windows\\System32"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native runtime validation")
def test_verification_rejects_a_qt_runtime_that_cannot_load(
    rebuild: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from subprocess import CompletedProcess

    for name in (
        "check_executable",
        "check_rule_packs",
        "check_metadata",
        "check_no_browser_engine",
    ):
        monkeypatch.setattr(rebuild, name, lambda bundle: None)
    monkeypatch.setattr(
        rebuild.subprocess,
        "run",
        lambda args, **kwargs: CompletedProcess(args, 1, "", "QtCore: missing procedure"),
    )
    errors = rebuild.verify(tmp_path)
    assert errors and "Qt runtime" in errors[0]
    assert "missing procedure" in errors[0]
