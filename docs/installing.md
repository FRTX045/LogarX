# Installing

Requires **Python 3.11 or newer**. The engine and the developer tools are tested on
Linux and Windows, Python 3.11 and 3.12, on every push.

**The desktop application is built and packaged for Windows, and runs on Linux.**
Its tests run on Linux headless (`QT_QPA_PLATFORM=offscreen`), and on
2026-10-05 it was also run on real display servers: Ubuntu 24.04 under WSLg,
Qt 6.11, once on Wayland and once on X11 (XWayland). Both opened a case, listed
its clients, drew a client's graph, showed the evidence behind an activity and
switched between Triage, Trace and Behaviour, with no warning from Qt
and a clean exit. What that run did not cover: a full GNOME or KDE session on
real hardware, native file dialogs, and HiDPI scaling. macOS has neither a
runner nor a report.

On X11, Qt needs a few XCB libraries that minimal installs leave out. The
symptom is *"Could not load the Qt platform plugin "xcb""*; on Debian and
Ubuntu the fix is:

```bash
sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 \
  libxcb-keysyms1 libxcb-render-util0 libxcb-shape0 libxcb-xkb1 libxcb-util1
```

Wayland needed nothing beyond what the system already had. That smoke test did
not cover leaving graph fullscreen from a maximized window. On 2026-10-17, that
transition reproduced a fatal WSLg Wayland protocol error (configured size
`0 × 0`). An X11 workaround survived the transition but introduced incorrect
borderless-window bounds and cursor hit positions. The application now keeps
Qt's normal backend selection and briefly unmaps the WSL Wayland window before
restoring it maximized, avoiding the failing transition with a fresh surface. See
[WSL display behavior](desktop-app.md).

```bash
pip install -e ".[gui]"      # the tool and the desktop application
pip install -e "."           # the engine and developer tools alone
pip install -e ".[dev]"      # add the test and lint toolchain
```

## A packaged Windows build

```bash
pip install -e ".[gui,package,dev]"
python packaging/rebuild.py
```

`dev` as well, because the script runs the test suite, across every core with
pytest-xdist, before it builds anything; a red suite stops the build.

Produces `dist/logarc/` (~270 MB), which runs without Python installed, and
with CRS enrichment working: the script builds the CRS sidecar and bundles it
with the ruleset and the licences of everything compiled into it, so the build
needs Go and the ruleset clone described under *OWASP CRS* below.

The licences of what it ships go under `_internal/licenses/`: each Python
package, Qt and PyInstaller included, CPython and the native libraries it links,
such as libffi, OpenSSL and expat, and the third-party code compiled into Qt
(HarfBuzz, FreeType, libpng, zlib, PCRE2 and more). They are committed in
`packaging/third-party/` and copied in as they are, so **after adding or
upgrading a dependency, or upgrading Qt, refresh them** as
[packaging/third-party/README.md](../packaging/third-party/README.md) describes:
`pip-licenses` for the Python packages, and
`packaging/fetch_qt_attributions.py` for Qt. The build stops while the Qt
notices are for a different Qt version from the one installed, and does not
otherwise check that the list is current.

**Not covered yet: Qt PDF, Qt Network and the software OpenGL renderer.** They
ship in the bundle, and the third-party code they carry (PDFium, the Public
Suffix List and libpsl, and Mesa) has no notice there. Gather those before the
folder is distributed.

One folder rather than one file: a one-file build unpacks the whole bundle to
`%TEMP%` on every launch, which with Qt and Arrow in it costs seconds each time
and leaves copies of the tool behind.

Use `rebuild.py` rather than `pyinstaller` directly, because **PyInstaller exits
0 on a bundle that is missing what it could not see** — the rule packs are data
that nothing imports, and a build without them reports every request as benign.
The script builds the CRS sidecar, runs the tests against it, builds into a
staging directory, checks for the things an exit code cannot, and only then
swaps the result into place. One of those checks sends the bundled sidecar a
SQL injection and requires CRS rule 942100 to answer, so a bundle whose CRS
starts but cannot find its rules is refused.

The staging checks also load the packaged Qt extensions in an isolated process.
Windows system DLLs take precedence during collection, so unrelated tools on
`PATH` cannot substitute an incompatible ICU library and break GUI startup.

It builds the working tree, so it also refuses a tree that moved while it ran.
A branch switch, a pull or an edit during those minutes would leave the tests,
the sidecar and PyInstaller each reading something different. When that
happens nothing is swapped in, and the status file says what moved. Run it
again once the tree is settled.

## OWASP CRS

The bundled rules classify *behaviour*; OWASP CRS enumerates payload *syntax*,
which is a different job and one it does far better. Both run, and CRS never
overrides a rule that examined the request — it names the ones nothing else
recognised.

**It runs after every scan, without asking.** The window replays each new case
through CRS on a card that can be stopped, keeping what it found so far, and
`logarc-dev ingest` does the same once the log is read. A stopped run is recorded
as one: the window, `analyze`, `evaluate` and every exported report say how many
requests CRS read, and stopping a rerun over a case already checked in full
keeps that earlier result. To turn it off:

| Where | How |
|---|---|
| The window | Edit → Preferences → General → *Run OWASP CRS after a scan* |
| One `ingest` | `--no-crs` (and `--crs` asks for it whatever the machine says) |
| A whole machine, both | `LOGARC_CRS=off` |

Turned off or not, *Case → Run CRS scan* runs it on the open
case whenever asked, as `logarc-dev enrich` does on the command line.

The packaged Windows build carries the sidecar and the ruleset, so there is
nothing to install. From source, set them up once:

```bash
logarc-dev setup-crs                                # needs git, Go 1.25+ and a connection, once
logarc-dev enrich --case ./case-shop --paranoia 3   # run again, at another level
```

`setup-crs` fetches the ruleset at the revision this project measures against
(`d694d465951ee06347214f1291ae096e40700001`), builds the sidecar, and replays a
known SQL injection to prove the two work together. It is the one time logarc
reaches for the network, and only because it was asked to. (In the window,
**Help → User guide** opens the online guide in your browser.) The manual steps are
in [crs/README.md](../crs/README.md).

Without the sidecar, a scan says once that CRS was not run and carries on: the
case analyses on the bundled rules alone, and says so on every run.
