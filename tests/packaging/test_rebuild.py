"""The swap that puts a verified build in place.

`packaging/rebuild.py` is a script rather than part of the package, so it is
loaded here by path. It is worth testing anyway: it is the only thing standing
between a red suite and a broken `dist/logarc`, and it runs unattended from a
git hook where nobody reads its output.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
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
        "check_crs",
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


def test_verification_rejects_a_bundle_without_the_crs_sidecar(
    rebuild: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "_internal").mkdir()

    problem = rebuild.check_crs(tmp_path)

    assert problem is not None and "CRS" in problem


def _bundled_crs(tmp_path: Path) -> Path:
    """A bundle holding copies of this checkout's built sidecar and ruleset."""
    from logarc.detect.crs import SidecarConfig, binary_name

    config = SidecarConfig()
    internal = tmp_path / "bundle" / "_internal"
    (internal / "crs").mkdir(parents=True)
    shutil.copy2(config.binary, internal / "crs" / binary_name())
    for name in ("coraza.conf", "crs-setup.conf"):
        shutil.copy2(config.conf / name, internal / "crs" / name)
    rules = internal / "vendor" / "coreruleset" / "rules"
    rules.mkdir(parents=True)
    for path in (config.rules / "rules").glob("REQUEST-*.conf"):
        shutil.copy2(path, rules / path.name)
    for path in (config.rules / "rules").glob("*.data"):
        shutil.copy2(path, rules / path.name)
    (rules.parent / "REVISION").write_text("d694d465\n", encoding="utf-8")
    return tmp_path / "bundle"


_CRS_BUILT = (
    ROOT / "crs" / ("crs-sidecar.exe" if sys.platform == "win32" else "crs-sidecar")
).exists() and (ROOT / "vendor" / "coreruleset" / "rules").is_dir()


@pytest.mark.skipif(
    not _CRS_BUILT and os.environ.get("LOGARC_REQUIRE_CRS") != "1",
    reason="CRS sidecar or ruleset not built; see crs/README.md",
)
def test_verification_runs_the_bundled_sidecar_on_a_known_attack(
    rebuild: ModuleType, tmp_path: Path
) -> None:
    """Present is not the same as working: the check sends it a request."""
    assert rebuild.check_crs(_bundled_crs(tmp_path)) is None


@pytest.mark.skipif(
    not _CRS_BUILT and os.environ.get("LOGARC_REQUIRE_CRS") != "1",
    reason="CRS sidecar or ruleset not built; see crs/README.md",
)
def test_verification_rejects_a_bundled_ruleset_with_a_rule_file_missing(
    rebuild: ModuleType, tmp_path: Path
) -> None:
    """A partial copy does not even load: crs-setup.conf tunes rules by id."""
    bundle = _bundled_crs(tmp_path)
    rules = bundle / "_internal" / "vendor" / "coreruleset" / "rules"
    (rules / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf").unlink()

    problem = rebuild.check_crs(bundle)

    assert problem is not None and "does not run" in problem


def _probe_says(
    rebuild: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stdout: str
) -> str | None:
    from subprocess import CompletedProcess

    (tmp_path / "_internal" / "crs").mkdir(parents=True)
    monkeypatch.setattr(
        rebuild.subprocess, "run", lambda args, **kwargs: CompletedProcess(args, 0, stdout, "")
    )
    return rebuild.check_crs(tmp_path)


PROBE_MISSED = "revision d694d465\nrules 920100\n"
PROBE_UNNAMED = "revision None\nrules 942100\n"
PROBE_GOOD = "revision d694d465\nrules 942100 949110\n"


def test_verification_rejects_a_sidecar_that_runs_but_misses_the_probe(
    rebuild: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    problem = _probe_says(rebuild, monkeypatch, tmp_path, PROBE_MISSED)

    assert problem is not None and "942100" in problem


def test_verification_rejects_a_ruleset_that_names_no_revision(
    rebuild: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    problem = _probe_says(rebuild, monkeypatch, tmp_path, PROBE_UNNAMED)

    assert problem is not None and "REVISION" in problem


def test_verification_accepts_a_probe_that_found_942100(
    rebuild: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _probe_says(rebuild, monkeypatch, tmp_path, PROBE_GOOD) is None


# -- the tree it builds ----------------------------------------------------
#
# The post-merge hook starts a rebuild in the background and hands the prompt
# back, so the tree can move under it: a `git checkout` while the suite runs,
# and the tests, the sidecar and PyInstaller each read whichever branch was
# there at the moment they looked. These run the real sequence against a real
# repository, with the slow steps stubbed, and move the tree where the suite
# would be running.


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _commit(repo: Path, text: str) -> None:
    (repo / "a.py").write_text(text, encoding="utf-8")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-q", "-m", text.strip())


@pytest.fixture
def tree(rebuild: ModuleType, bundles: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository standing in for the checkout, every slow step stubbed."""
    repo = bundles / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "rebuild@example.invalid")
    _git(repo, "config", "user.name", "rebuild")
    _git(repo, "config", "core.autocrlf", "false")
    _commit(repo, "x = 1\n")

    def build() -> tuple[bool, str]:
        _staged(rebuild)
        return True, ""

    monkeypatch.setattr(rebuild, "ROOT", repo)
    monkeypatch.setattr(rebuild, "GIT_DIR", repo / ".git")
    monkeypatch.setattr(rebuild, "STATUS", bundles / "dist" / "BUILD-STATUS.txt")
    monkeypatch.setattr(rebuild, "MARKER", repo / ".git" / "logarc-build-failed")
    monkeypatch.setattr(rebuild.crs_bundle, "prepare", lambda: [])
    monkeypatch.setattr(rebuild, "build", build)
    monkeypatch.setattr(rebuild, "verify", lambda bundle: [])
    monkeypatch.setattr(rebuild, "size_mb", lambda path: 1.0)
    return repo


def _while_testing(rebuild: ModuleType, monkeypatch: pytest.MonkeyPatch, move) -> None:
    def run_tests() -> tuple[bool, str]:
        move()
        return True, ""

    monkeypatch.setattr(rebuild, "run_tests", run_tests)


def test_a_quiet_tree_is_built_and_stamped_with_its_commit(
    rebuild: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _while_testing(rebuild, monkeypatch, lambda: None)
    built = _git(tree, "rev-parse", "--short", "HEAD")

    assert rebuild._rebuild() == 0
    assert (rebuild.LIVE / "logarc.exe").exists()
    assert rebuild.STATUS.read_text(encoding="utf-8").split()[2] == built


def test_a_branch_switched_during_the_run_is_not_put_in_place(
    rebuild: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def switch() -> None:
        _git(tree, "checkout", "-q", "-b", "feat/x")
        _commit(tree, "x = 2\n")

    _while_testing(rebuild, monkeypatch, switch)

    assert rebuild._rebuild() == 1
    assert not rebuild.LIVE.exists()
    assert "NOT REBUILT" in rebuild.STATUS.read_text(encoding="utf-8")
    assert "changed while it was being built" in rebuild.MARKER.read_text(encoding="utf-8")


def test_a_switch_away_and_back_during_the_run_is_caught(
    rebuild: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HEAD ends where it started, but the build read the other branch meanwhile."""

    def away_and_back() -> None:
        _git(tree, "checkout", "-q", "-b", "feat/x")
        _commit(tree, "x = 2\n")
        _git(tree, "checkout", "-q", "main")

    _while_testing(rebuild, monkeypatch, away_and_back)

    assert rebuild._rebuild() == 1
    assert not rebuild.LIVE.exists()


def test_an_edit_during_the_run_is_caught(
    rebuild: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _while_testing(
        rebuild, monkeypatch, lambda: (tree / "a.py").write_text("x = 3\n", encoding="utf-8")
    )

    assert rebuild._rebuild() == 1
    assert not rebuild.LIVE.exists()


def test_an_edit_already_there_at_the_start_does_not_stop_it(
    rebuild: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rebuild by hand of uncommitted work is allowed; only movement is refused."""
    (tree / "a.py").write_text("x = 4\n", encoding="utf-8")
    _while_testing(rebuild, monkeypatch, lambda: None)

    assert rebuild._rebuild() == 0


def test_a_second_edit_to_a_modified_file_is_caught(
    rebuild: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`git status` says ` M a.py` before and after; only the content moved."""
    (tree / "a.py").write_text("x = 4\n", encoding="utf-8")
    _while_testing(
        rebuild, monkeypatch, lambda: (tree / "a.py").write_text("x = 5\n", encoding="utf-8")
    )

    assert rebuild._rebuild() == 1
