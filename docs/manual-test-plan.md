# Manual test plan — the desktop application

The engine is covered by the automated suite. The window is not, and mostly
cannot be: "the interface stayed responsive", "the node the investigator clicked
is the one whose evidence appeared", and "the exported report says the same
thing the screen said" are judgements about what a person sees. This is the
checklist that makes those judgements repeatable instead of impressionistic.

Run it before tagging a release, and after any change to `src/logarc/gui/` or to
the packaging spec.

## What is already automated, and therefore not here

| Covered by | What it proves |
|---|---|
| `tests/gui/test_style.py` | Colour follows severity, border follows outcome, node size follows volume. These decide whether a graph misinforms, so they are kept out of Qt and tested directly. |
| `tests/gui/test_window.py` | The window constructs, the canvas draws a real reconstruction and an empty one, the client table lists and sorts, the evidence panel shows raw lines and reports an unreadable source, and the cancel button reaches the flag the engine polls. |
| `tests/test_case_workflow.py` | A cancelled ingest leaves the case un-finalised and still records the files that completed. |

What is left below is everything that needs eyes.

## Fixture

One command, and the same log every time — the seed is fixed, so a failure here
is reproducible on someone else's machine.

```powershell
# ~1.2 GB, enough that ingest takes long enough to watch
.venv\Scripts\logarc.exe generate -s mixed -n 10000000 -o fixture\big.log

# small, fast, and with a known attacker in it
.venv\Scripts\logarc.exe generate -s sqli_campaign -n 40000 -o fixture\small.log
```

Start the application with `.venv\Scripts\logarc-gui.exe`, or the packaged
`dist\logarc\logarc.exe` when checking a build.

---

## 1. A large ingest does not freeze the window

**Why:** every engine call is supposed to run on a worker thread. A blocking
call would not fail — it would just make a busy tool indistinguishable from a
hung one, which is how an investigator ends up killing a run that was working.

1. **Case → Ingest logs into a new case…**, choose `fixture\big.log`, choose an
   empty target folder.
2. While it runs: drag the window, resize it, drag the splitter between the
   panels, open the **View** menu.

**Pass:** the window redraws throughout. The status bar line-count keeps
climbing. Windows never greys the title bar or offers to close the program.

**Fail:** any pause longer than about a second where the window does not repaint.

---

## 2. Cancelling mid-ingest leaves the case honestly incomplete

**Why:** the dangerous outcome is not a failed cancel, it is a half-read log
that presents as a whole one. Everything downstream — every count, every
"outcome: blocked", every absence of a finding — would be wrong in a way nothing
on screen would show.

1. Start the same ingest again into a *different* empty folder.
2. Once the count passes a million lines, press **Cancel**.

**Pass:** the button greys and the status bar reads "Stopping after the batch in
flight…". Within a few seconds a dialog reports how many lines were read and
says the case was not finalised. The folder still exists — the application must
not delete a directory the user chose.

3. Now try to open that folder with **Case → Open case…**.

**Pass:** a dialog reporting that the case has not been finalised. No client
list appears. The partial case must never present as an analysable one — a
cancelled case is discarded, not resumed.

4. Confirm the same from the command line, which reads the case independently:

```powershell
.venv\Scripts\logarc.exe list-ips -c <cancelled-case>
```

**Pass:** the same refusal, naming the same reason. If the CLI can analyse a
case the GUI called incomplete, one of the two is lying.

---

## 3. Clicking a node shows the log lines that node was built from

**Why:** this is the whole claim of the tool. A node whose evidence panel shows
somebody else's requests is worse than no tool at all, because it is wrong with
a citation attached.

1. Open the case built from `fixture\small.log`.
2. Pick the client with the most requests. Wait for the graph.
3. Click the reddest node.
4. Read the panel: the heading names the activity, and the body lists
   `file:line` references with the raw line under each.
5. Check three of them against the log itself:

```powershell
# for a reference shown as small.log:41337
(Get-Content fixture\small.log)[41336]   # 0-indexed, so line N is index N-1
```

**Pass:** the text in the panel is byte-for-byte the line in the file, the
client address in it is the client selected, and its timestamp falls inside the
window shown in the heading.

6. Compare with the CLI, which builds the same evidence a different way:

```powershell
.venv\Scripts\logarc.exe evidence -c <case> --ip <address> -n 25
```

**Pass:** the same references for the same activity.

---

## 4. Trace and behaviour describe the same reconstruction

**Why:** the behaviour map is a fold over the trace. If the two disagree, one of
them is not derived from the analysis on screen.

1. With a client reconstructed, switch **View → Behaviour map**, then back to
   **View → Trace**.

**Pass:** every activity type in the trace appears exactly once in the behaviour
map. Severity colours and outcome borders match for the same activity. Request
counts on behaviour nodes equal the sum over the trace nodes of that type. The
heading above the canvas does not change — it describes the client, not the
view.

2. Click a node in each view.

**Pass:** both open evidence for the same activity, showing the same lines.

---

## 5. What is exported matches what was on screen

**Why:** the report is what leaves the building. If it disagrees with the
screen, the screen was a preview of nothing.

1. **Export → HTML report…**, then **Export → JSON graph…**, then
   **Export → PNG image…**.
2. Produce the CLI's version of the same client:

```powershell
.venv\Scripts\logarc.exe export -c <case> --ip <address> -f json -o cli-graph.json
.venv\Scripts\logarc.exe analyze -c <case> --ip <address> -o cli-analysis.json
```

**Pass:** the GUI's JSON and the CLI's JSON describe the same nodes, edges and
evidence references. The HTML report opens in a browser with no network access
and shows the same activities and the same manifest. The PNG shows the graph as
drawn, in the view that was on screen when it was exported.

3. Export with nothing reconstructed.

**Pass:** "Reconstruct a client first" — not an empty file.

---

## 6. Failures are visible

**Why:** a forensic tool that fails quietly has produced a result nobody can
trust and nobody can question.

1. Open a case, reconstruct a client, then rename or move the original log file.
2. Click a node.

**Pass:** the evidence panel says the source is unavailable and names it. It
does not show blank lines where evidence should be, and it does not crash.

3. Point **Case → Open case…** at an ordinary folder that is not a case.

**Pass:** a dialog explaining that, with the traceback available under
**Show Details**. The window stays usable afterwards.

---

## 7. The packaged build

**Why:** the bundle is a different program from the one the tests ran against.
Data files that are never imported — the rule packs — and package metadata are
exactly what a freezer drops, and both fail at runtime rather than at build time.

```powershell
pip install -e ".[gui,package]"
pyinstaller --clean --noconfirm packaging\logarc.spec
```

Then, on the built `dist\logarc\logarc.exe`:

1. Launch it on a machine, or in an account, with no Python installed.

**Pass:** the window opens. No console window appears alongside it.

2. Ingest `fixture\small.log` and reconstruct the busiest client.

**Pass:** attack activities are found. **If every request comes back benign, the
rule packs did not make it into the bundle** — that is the failure this step
exists to catch, and it looks exactly like a clean log.

3. Open `case.json` in the case the packaged build just created.

**Pass:** `tool_version` reads the real version, not `0.0.0.dev0`. The frozen
build reads its own package metadata for this, and the manifest is where a
report says which version of the tool produced it.

4. Check the folder.

**Pass:** roughly 250 MB, with no `QtWebEngine*` in `_internal\` — the canvas is
QGraphicsView specifically so no browser engine ships (ADR-0006).

---

## Recording a run

| # | Check | Result | Notes |
|---|---|---|---|
| 1 | Large ingest stays responsive | | |
| 2 | Cancel leaves the case honestly incomplete | | |
| 3 | Node evidence matches the source lines | | |
| 4 | Trace and behaviour agree | | |
| 5 | Export matches the screen and the CLI | | |
| 6 | Failures are visible | | |
| 7 | Packaged build finds its rules and knows its version | | |

Version tested: ______  ·  Date: ______  ·  Machine: ______
