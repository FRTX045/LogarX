# PyInstaller build for the Windows desktop application.
#
#     pip install -e ".[gui,package]"
#     pyinstaller --clean --noconfirm packaging/logarc.spec
#
# Produces dist/logarc/, which runs on a machine with no Python on it.
#
# One folder, not one file. A one-file build unpacks the whole bundle into a
# temporary directory on every launch, which with Qt and Arrow in it costs
# seconds each time and leaves copies of the tool in %TEMP%. Neither is
# something an investigator should have to explain.

import sys
from pathlib import Path, PurePosixPath

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

PROJECT = Path(SPECPATH).parent

# Rule packs are data, not code, so nothing imports them and PyInstaller cannot
# see them. Without them the build starts, finds no rules, and reports every
# request as benign — a failure that looks like a clean log.
#
# Collected by walking rather than by a glob, and each one is placed back at the
# path it came from. The packs are grouped into folders (`attack/php.yaml`), and
# a `*.yaml` glob sees one level: it would have bundled nothing at all here,
# quietly, while every other part of the build succeeded.
RULEPACKS = PROJECT / "src" / "logarc" / "detect" / "rulepacks"
_packs = sorted(RULEPACKS.rglob("*.yaml"))
if not _packs:
    raise SystemExit(f"no rule packs under {RULEPACKS}; the build would detect nothing")

datas = [
    *(
        (str(pack), (PurePosixPath("logarc/detect/rulepacks") / pack.relative_to(RULEPACKS).parent).as_posix())
        for pack in _packs
    ),
    (str(PROJECT / "LICENSE"), "."),
    # The icon set the graph draws from, and the notice its licence asks to go
    # wherever it does: Lucide's ISC terms are in NOTICE.
    (str(PROJECT / "src" / "logarc" / "gui" / "lucide.json"), "logarc/gui"),
    (str(PROJECT / "NOTICE"), "."),
]

# `logarc.__version__` reads its own package metadata, and that metadata is
# what the case manifest records as `tool_version`. PyInstaller does not bundle
# dist-info unless asked, so without this every case produced by the packaged
# build would be stamped 0.0.0.dev0 — a report that cannot say which version of
# the tool made it, which is the one thing the manifest is for.
datas += copy_metadata("logarc")

# The CRS sidecar, its ruleset and the licences of what is compiled into it,
# placed where `logarc.detect.crs.sidecar` looks when frozen. Neither is Python,
# so PyInstaller cannot find them; `crs_bundle.datas()` raises rather than
# returning a short list, so a build without them stops here instead of shipping
# an application whose CRS enrichment fails on someone else's machine.
# `packaging/rebuild.py` builds and stages all of it first.
sys.path.insert(0, SPECPATH)
import crs_bundle  # noqa: E402

try:
    datas += crs_bundle.datas()
except crs_bundle.CrsBundleError as exc:
    raise SystemExit(str(exc)) from exc

hiddenimports = [
    # Parsers register themselves on import. Only the ones actually referenced
    # would otherwise be traced, and a format the user picks from the dialog
    # would be missing at runtime rather than at build time.
    *collect_submodules("logarc.parsers"),
]

excludes = [
    # Development tooling. Present in the venv the build runs from, no business
    # in what ships.
    "pytest",
    "hypothesis",
    "mypy",
    "ruff",
    "IPython",
    "setuptools",
    # Never imported, and each drags in a large dependency tree.
    "tkinter",
    "matplotlib",
    "PIL",
    "pandas",
    # ADR-0006: the canvas is QGraphicsView precisely so no browser engine is
    # needed. QtWebEngine alone is a few hundred megabytes; letting it in would
    # undo the reason for the decision.
    "PyQt6.QtWebEngineCore",
    "PyQt6.QtWebEngineWidgets",
    "PyQt6.QtWebEngineQuick",
    "PyQt6.QtQuick",
    "PyQt6.QtQml",
    "PyQt6.Qt3DCore",
    "PyQt6.QtMultimedia",
    "PyQt6.QtBluetooth",
    "PyQt6.QtNfc",
    "PyQt6.QtPositioning",
    "PyQt6.QtSerialPort",
    "PyQt6.QtDesigner",
    "PyQt6.QtTest",
]

analysis = Analysis(
    [str(PROJECT / "packaging" / "logarc_gui.py")],
    pathex=[str(PROJECT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

# The licences of everything collected above, Qt, CPython and the native
# libraries CPython links included, under licenses/. Read from what was
# collected rather than from the dependency list, so the command line kept out
# of the bundle brings no notice for code it does not contain; `licences.datas()`
# raises for anything shipped without a licence, which stops the build here.
import licences  # noqa: E402

try:
    analysis.datas += [
        ((PurePosixPath(dest) / Path(source).name).as_posix(), source, "DATA")
        for source, dest in licences.datas(
            scripts=(entry[1] for entry in analysis.scripts),
            pure=(entry[0] for entry in analysis.pure),
            binaries=(entry[0] for entry in analysis.binaries),
        )
    ]
except licences.LicenceError as exc:
    raise SystemExit(str(exc)) from exc

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="logarc",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed binaries are a routine antivirus false positive.
    # No console window. A crash is not lost by this: the failure dialog carries
    # the full traceback under "Show Details", which is where someone running a
    # windowed build would look for it.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="logarc",
)
