"""`tools/hooks/` stops a commit CI's lint job would reject, and keeps `dist/` current.

Turned on with `git config core.hooksPath tools/hooks`. The two rebuild hooks do
nothing unless `git config logarc.rebuild true` asks for them, because most
checkouts never build the Windows application.

Each test makes a repository of its own, points it at these hooks, and does what
a developer does - commits, branches, merges - then reads what git printed. The
rebuild a hook starts is a stub in that repository, so what is checked is the
decision to start one, which is where the faults have been: a rebuild placed
after an `exit 0` that never ran during a real merge, and commits made straight
on `main` that fired no rebuild at all.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from shell import bash

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "tools" / "hooks"
NAMES = ("pre-commit", "post-commit", "post-merge", "post-checkout")

REBUILDING = "rebuilding dist/ in the background"
UNCHANGED = "nothing in the bundle changed"


class Repo:
    """A repository of the test's own, with these hooks turned on."""

    def __init__(self, root: Path, env: dict[str, str]) -> None:
        self.root = root
        self.env = env
        self.build_log = Path(env["HOME"]) / ".cache" / "logarc-build.log"

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, capture_output=True, text=True
        )

    def commit(self, path: str, text: str = "x = 1\n") -> subprocess.CompletedProcess[str]:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
        self.git("add", path)
        return self.git("commit", "-q", "-m", f"change {path}")

    def ask_for_rebuilds(self) -> None:
        self.git("config", "logarc.rebuild", "true")


def said(done: subprocess.CompletedProcess[str]) -> str:
    """Everything git printed, the hooks' output included."""
    return done.stdout + done.stderr


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    home = tmp_path / "home"
    home.mkdir()
    # Nothing of git's own may leak in. A rebuild runs this suite from inside a
    # hook, where git has exported GIT_DIR: left in place, every command here
    # would act on this repository instead of the one made for the test.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(HOME=str(home), GIT_CONFIG_GLOBAL=str(home / ".gitconfig"), GIT_CONFIG_NOSYSTEM="1")
    root = tmp_path / "repo"
    root.mkdir()
    made = Repo(root, env)
    made.git("init", "-q", "-b", "main")
    made.git("config", "user.name", "Test")
    made.git("config", "user.email", "test@example.com")
    made.git("config", "core.hooksPath", HOOKS.as_posix())
    # What a rebuild would run: a stub, so nothing real is ever built from here.
    (root / "packaging").mkdir()
    (root / "packaging" / "rebuild.py").write_text('print("stub")\n', encoding="utf-8")
    made.git("add", "-A")
    made.git("commit", "-q", "-m", "start")
    return made


def test_every_hook_is_valid_sh() -> None:
    for name in (*NAMES, "rebuild-warning.sh"):
        subprocess.run([bash(), "-n", str(HOOKS / name)], check=True)


def test_every_hook_is_committed_executable() -> None:
    """Git on Linux and macOS skips a hook without its executable bit, with a
    hint that is easy to miss. Windows does not check, so a hook written there
    is committed without the bit unless it is asked for."""
    listed = subprocess.run(
        ["git", "ls-files", "--stage", "tools/hooks"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    modes = {
        line.split("\t")[1].rsplit("/", 1)[-1]: line.split()[0] for line in listed.splitlines()
    }

    assert {name: modes.get(name) for name in NAMES} == dict.fromkeys(NAMES, "100755")


def _ruff() -> Path:
    name = "ruff.exe" if os.name == "nt" else "ruff"
    here = Path(sys.executable).parent
    for candidate in (here / name, here / "Scripts" / name, Path(shutil.which("ruff") or "")):
        if candidate.is_file():
            return candidate
    pytest.skip("ruff is not installed beside this interpreter")


def _give_it_ruff(repo: Repo) -> None:
    """Put ruff where the hook looks: the checkout's own `.venv`."""
    target = repo.root / ".venv" / ("Scripts/ruff.exe" if os.name == "nt" else "bin/ruff")
    target.parent.mkdir(parents=True)
    try:
        os.link(_ruff(), target)
    except OSError:
        shutil.copy2(_ruff(), target)


def test_a_commit_ci_would_reject_for_its_formatting_is_stopped(repo: Repo) -> None:
    _give_it_ruff(repo)

    done = repo.commit("src/a.py", "x=1\n")

    assert done.returncode != 0
    assert "this is what CI's lint job would say" in said(done)


def test_a_commit_ci_would_accept_goes_through(repo: Repo) -> None:
    _give_it_ruff(repo)

    done = repo.commit("src/a.py", "x = 1\n")

    assert done.returncode == 0, said(done)


def test_without_a_venv_the_lint_check_steps_aside(repo: Repo) -> None:
    done = repo.commit("src/a.py", "x=1\n")

    assert done.returncode == 0
    assert "no ruff in .venv" in said(done)


def test_a_commit_on_main_that_changes_the_bundle_rebuilds_it(repo: Repo) -> None:
    repo.ask_for_rebuilds()

    assert REBUILDING in said(repo.commit("src/logarc/a.py"))
    assert "post-commit" in repo.build_log.read_text(encoding="utf-8")


#: What `go build` compiles into the bundled CRS sidecar. A security bump of
#: Coraza touched only these, and left the application shipping the old one.
SIDECAR = ("crs/go.mod", "crs/go.sum", "crs/main.go")


@pytest.mark.parametrize("path", SIDECAR)
def test_a_commit_on_main_that_changes_the_sidecar_rebuilds_it(repo: Repo, path: str) -> None:
    repo.ask_for_rebuilds()

    assert REBUILDING in said(repo.commit(path))


@pytest.mark.parametrize("path", SIDECAR)
def test_a_merge_into_main_that_changes_the_sidecar_rebuilds_it(repo: Repo, path: str) -> None:
    repo.ask_for_rebuilds()
    repo.git("checkout", "-q", "-b", "fix/x")
    repo.commit(path)
    repo.git("checkout", "-q", "main")

    done = repo.git("merge", "--no-ff", "-q", "-m", "merge", "fix/x")

    assert REBUILDING in said(done)


def test_the_sidecars_readme_rebuilds_nothing(repo: Repo) -> None:
    repo.ask_for_rebuilds()

    assert REBUILDING not in said(repo.commit("crs/README.md"))


def test_nothing_is_rebuilt_unless_asked_for(repo: Repo) -> None:
    committed = said(repo.commit("src/logarc/a.py"))
    repo.git("checkout", "-q", "-b", "feat/x")
    repo.commit("src/logarc/b.py")
    repo.git("checkout", "-q", "main")
    merged = said(repo.git("merge", "--no-ff", "-q", "-m", "merge", "feat/x"))

    assert REBUILDING not in committed + merged
    assert UNCHANGED not in merged
    assert not repo.build_log.exists()


def test_a_commit_on_a_branch_waits_for_its_merge(repo: Repo) -> None:
    repo.ask_for_rebuilds()
    repo.git("checkout", "-q", "-b", "feat/x")

    assert REBUILDING not in said(repo.commit("src/logarc/a.py"))


def test_a_commit_on_main_that_changes_only_documents_rebuilds_nothing(repo: Repo) -> None:
    repo.ask_for_rebuilds()

    assert REBUILDING not in said(repo.commit("docs/a.md"))


def test_a_merge_into_main_that_changes_the_bundle_rebuilds_it(repo: Repo) -> None:
    repo.ask_for_rebuilds()
    repo.git("checkout", "-q", "-b", "feat/x")
    repo.commit("src/logarc/a.py")
    repo.git("checkout", "-q", "main")

    done = repo.git("merge", "--no-ff", "-q", "-m", "merge", "feat/x")

    assert done.returncode == 0, said(done)
    assert REBUILDING in said(done)
    assert "post-merge" in repo.build_log.read_text(encoding="utf-8")


def test_a_merge_into_main_that_changes_only_documents_says_so(repo: Repo) -> None:
    repo.ask_for_rebuilds()
    repo.git("checkout", "-q", "-b", "docs/x")
    repo.commit("docs/a.md")
    repo.git("checkout", "-q", "main")

    done = repo.git("merge", "--no-ff", "-q", "-m", "merge", "docs/x")

    assert UNCHANGED in said(done)
    assert REBUILDING not in said(done)


def test_a_failed_rebuild_is_reported_while_its_marker_stands(repo: Repo) -> None:
    marker = repo.root / ".git" / "logarc-build-failed"
    marker.write_text("the tests failed", encoding="utf-8")

    assert "dist/ was NOT rebuilt: the tests failed" in said(repo.git("checkout", "-b", "x"))

    marker.unlink()

    assert "NOT rebuilt" not in said(repo.git("checkout", "main"))
