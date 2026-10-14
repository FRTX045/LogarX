"""What the packaged application carries so CRS works in it.

`packaging/crs_bundle.py` decides which files go in and where, and the spec
refuses to build without them. The layout has to match the one
`logarc.detect.crs.sidecar` looks in when frozen, or the application ships the
sidecar and still cannot find it — so the mapping is checked against the paths
that code resolves, not against a second copy of them written here.
"""

from __future__ import annotations

import importlib.util
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType

import pytest

from logarc.detect.crs import sidecar

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    path = ROOT / "packaging" / "crs_bundle.py"
    spec = importlib.util.spec_from_file_location("logarc_crs_bundle_script", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bundle() -> ModuleType:
    return _load()


def _tree(tmp_path: Path, *, binary: bool = True) -> tuple[Path, Path, Path]:
    """A source checkout with a built sidecar and a fetched ruleset."""
    crs = tmp_path / "crs"
    crs.mkdir()
    (crs / "coraza.conf").write_text("SecRuleEngine On\n")
    (crs / "crs-setup.conf").write_text("# setup\n")
    if binary:
        (crs / sidecar.binary_name()).write_bytes(b"MZ")
    ruleset = tmp_path / "vendor" / "coreruleset"
    (ruleset / "rules").mkdir(parents=True)
    (ruleset / "LICENSE").write_text("Apache-2.0\n")
    for name in (
        "REQUEST-901-INITIALIZATION.conf",
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "RESPONSE-950-DATA-LEAKAGES.conf",
        "sql-errors.data",
        "restricted-files.data",
    ):
        (ruleset / "rules" / name).write_text(name)
    stage = tmp_path / "build" / "crs-bundle"
    (stage / "licenses" / "github.com" / "corazawaf" / "coraza" / "v3").mkdir(parents=True)
    (stage / "REVISION").write_text("d694d465\n")
    (stage / "licenses" / "github.com" / "corazawaf" / "coraza" / "v3" / "LICENSE").write_text("x")
    return crs, ruleset, stage


def _placed(datas: list[tuple[str, str]]) -> set[str]:
    """Each bundled file as the path it ends up at under the bundle root."""
    return {(PurePosixPath(dest) / Path(source).name).as_posix() for source, dest in datas}


def test_the_bundle_puts_everything_where_the_frozen_application_looks(
    bundle: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    crs, ruleset, stage = _tree(tmp_path)
    placed = _placed(bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage))

    # Resolve the frozen paths with the real code, against an empty bundle root,
    # and require every one of them to be something the bundle provides.
    root = tmp_path / "frozen"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(root), raising=False)
    monkeypatch.delenv(sidecar.BINARY_ENV, raising=False)
    config = sidecar.SidecarConfig()

    def under_root(path: Path) -> str:
        return path.relative_to(root).as_posix()

    assert under_root(config.binary) in placed
    assert under_root(config.conf / "coraza.conf") in placed
    assert under_root(config.conf / "crs-setup.conf") in placed
    rules = under_root(config.rules)
    assert f"{rules}/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf" in placed
    assert f"{rules}/rules/sql-errors.data" in placed
    assert f"{rules}/REVISION" in placed
    assert f"{rules}/LICENSE" in placed


def test_response_rules_stay_out(bundle: ModuleType, tmp_path: Path) -> None:
    """The sidecar never loads them: an access log has no response body."""
    crs, ruleset, stage = _tree(tmp_path)

    placed = _placed(bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage))

    assert not any("RESPONSE-" in path for path in placed)


def test_the_go_licences_ship_beside_the_binary_they_cover(
    bundle: ModuleType, tmp_path: Path
) -> None:
    crs, ruleset, stage = _tree(tmp_path)

    placed = _placed(bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage))

    assert "licenses/crs-sidecar/github.com/corazawaf/coraza/v3/LICENSE" in placed


def test_the_notice_ships_at_the_bundle_root(bundle: ModuleType, tmp_path: Path) -> None:
    """NOTICE says it travels with any distribution containing a built sidecar,
    and the packaged application now is one."""
    crs, ruleset, stage = _tree(tmp_path)

    placed = _placed(bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage))

    assert "NOTICE" in placed


def test_a_missing_notice_stops_the_build(bundle: ModuleType, tmp_path: Path) -> None:
    crs, ruleset, stage = _tree(tmp_path)

    with pytest.raises(bundle.CrsBundleError, match="NOTICE"):
        bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage, notice=tmp_path / "NOTICE")


def test_a_missing_sidecar_stops_the_build(bundle: ModuleType, tmp_path: Path) -> None:
    """Rather than ship an application whose CRS button fails on someone else's
    machine, which is what a build without it did before."""
    crs, ruleset, stage = _tree(tmp_path, binary=False)

    with pytest.raises(bundle.CrsBundleError, match=sidecar.binary_name()):
        bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage)


def test_a_ruleset_without_request_rules_stops_the_build(
    bundle: ModuleType, tmp_path: Path
) -> None:
    crs, ruleset, stage = _tree(tmp_path)
    for path in (ruleset / "rules").glob("REQUEST-*.conf"):
        path.unlink()

    with pytest.raises(bundle.CrsBundleError, match="REQUEST-"):
        bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage)


def test_an_unrecorded_revision_stops_the_build(bundle: ModuleType, tmp_path: Path) -> None:
    """Without it every bundled case's CRS fingerprint says "unknown"."""
    crs, ruleset, stage = _tree(tmp_path)
    (stage / "REVISION").unlink()

    with pytest.raises(bundle.CrsBundleError, match="REVISION"):
        bundle.datas(crs_dir=crs, ruleset=ruleset, stage=stage)


def test_go_list_output_names_each_dependency_module_once(bundle: ModuleType) -> None:
    """The sidecar's own module is this project's, already licensed by LICENSE."""
    own = Path("C:/src/logarc/crs")
    output = "\n".join(
        [
            "",
            f"logarc/crs\t{own}",
            "github.com/corazawaf/coraza/v3\tC:/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.3.3",
            "github.com/corazawaf/coraza/v3\tC:/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.3.3",
            "rsc.io/binaryregexp\tC:/go/pkg/mod/rsc.io/binaryregexp@v0.2.0",
        ]
    )

    modules = bundle.modules_from_go_list(output, main_dir=own)

    assert [path for path, _ in modules] == [
        "github.com/corazawaf/coraza/v3",
        "rsc.io/binaryregexp",
    ]


def test_licence_files_are_copied_under_their_module_path(
    bundle: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "mod" / "coraza@v3"
    source.mkdir(parents=True)
    (source / "LICENSE").write_text("Apache")
    (source / "NOTICE").write_text("notice")
    (source / "main.go").write_text("package x")
    dest = tmp_path / "licenses"

    unlicensed = bundle.copy_licences([("github.com/corazawaf/coraza/v3", source)], dest)

    target = dest / "github.com" / "corazawaf" / "coraza" / "v3"
    assert sorted(path.name for path in target.iterdir()) == ["LICENSE", "NOTICE"]
    assert unlicensed == []


def test_licences_copied_from_a_read_only_module_cache_stay_deletable(
    bundle: ModuleType, tmp_path: Path
) -> None:
    """Go keeps its module cache read-only. Copying that flag along made the next
    build's clean-up fail with "Access is denied" on Windows, which stopped the
    first real post-merge rebuild."""
    source = tmp_path / "mod" / "coraza@v3"
    source.mkdir(parents=True)
    (source / "LICENSE").write_text("Apache")
    (source / "LICENSE").chmod(stat.S_IREAD)
    dest = tmp_path / "licenses"

    try:
        bundle.copy_licences([("github.com/corazawaf/coraza/v3", source)], dest)
        copied = dest / "github.com" / "corazawaf" / "coraza" / "v3" / "LICENSE"
        assert os.access(copied, os.W_OK)
    finally:
        (source / "LICENSE").chmod(stat.S_IREAD | stat.S_IWRITE)


def test_a_stage_left_with_read_only_files_is_still_cleared(
    bundle: ModuleType, tmp_path: Path
) -> None:
    """Builds made before the fix above left exactly this behind."""
    stage = tmp_path / "crs-bundle"
    (stage / "licenses" / "x").mkdir(parents=True)
    leftover = stage / "licenses" / "x" / "LICENSE"
    leftover.write_text("old")
    leftover.chmod(stat.S_IREAD)

    bundle.reset_stage(stage)

    assert stage.is_dir() and not any(stage.iterdir())


def test_a_module_with_no_licence_file_is_reported(bundle: ModuleType, tmp_path: Path) -> None:
    """Shipping a binary built from it without a notice is the thing to catch."""
    source = tmp_path / "mod" / "bare"
    source.mkdir(parents=True)

    unlicensed = bundle.copy_licences([("example.com/bare", source)], tmp_path / "licenses")

    assert unlicensed == ["example.com/bare"]


def test_code_compiled_into_a_module_ships_its_notices_beside_the_modules_own(
    bundle: ModuleType, tmp_path: Path
) -> None:
    """go-re2 carries RE2, wasi-libc and libc++ inside a WebAssembly module, and
    their licences are not in the Go module for the copy above to find."""
    source = tmp_path / "mod" / "go-re2@v1"
    source.mkdir(parents=True)
    (source / "LICENSE").write_text("MIT")
    kept = tmp_path / "crs" / "licenses" / "go-re2"
    (kept / "re2").mkdir(parents=True)
    (kept / "re2" / "LICENSE").write_text("BSD")
    dest = tmp_path / "licenses"

    unlicensed = bundle.copy_licences(
        [("github.com/wasilibs/go-re2", source)],
        dest,
        compiled_in={"github.com/wasilibs/go-re2": kept},
    )

    target = dest / "github.com" / "wasilibs" / "go-re2"
    assert (target / "LICENSE").read_text() == "MIT"
    assert (target / "compiled-in" / "re2" / "LICENSE").read_text() == "BSD"
    assert unlicensed == []


def test_compiled_in_code_whose_notices_are_missing_is_reported(
    bundle: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "mod" / "go-re2@v1"
    source.mkdir(parents=True)
    (source / "LICENSE").write_text("MIT")

    unlicensed = bundle.copy_licences(
        [("github.com/wasilibs/go-re2", source)],
        tmp_path / "licenses",
        compiled_in={"github.com/wasilibs/go-re2": tmp_path / "absent"},
    )

    assert unlicensed == ["github.com/wasilibs/go-re2 (the code compiled into it)"]


def test_every_module_with_code_compiled_in_has_its_notices_kept(bundle: ModuleType) -> None:
    kept = bundle.compiled_in(ROOT / "crs")

    assert kept, "nothing listed: go-re2 at least carries RE2 and libc++"
    for module, folder in kept.items():
        assert any(folder.rglob("LICENSE*")), f"{module}: no licence under {folder}"


def test_the_notices_kept_for_go_re2_are_for_the_version_the_sidecar_builds_with() -> None:
    """An upgrade may build from other versions of RE2 and the C library, or
    from other projects, so the list is read again whenever go-re2 moves."""
    go_mod = (ROOT / "crs" / "go.mod").read_text(encoding="utf-8")
    readme = (ROOT / "crs" / "licenses" / "go-re2" / "README.md").read_text(encoding="utf-8")

    required = re.search(r"github\.com/wasilibs/go-re2 (v[\w.-]+)", go_mod)
    described = re.search(r"`github\.com/wasilibs/go-re2` (v[\w.-]+)", readme)

    assert required and described
    assert described.group(1) == required.group(1)
