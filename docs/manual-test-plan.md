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

**Pass:** the window redraws throughout. The card's line count keeps climbing.
Windows never greys the title bar or offers to close the program.

**Fail:** any pause longer than about a second where the window does not repaint.

3. Watch the card itself, with **two logs — a small one first, then a large
   one**. That pair matters: the counts restart at every file, and inferring
   the boundary from the byte count falling misses it entirely when the whole
   of a small log is smaller than one batch of a large one.

**Pass:** the percentage only ever climbs, and the line count carries straight
through the change of file rather than dropping back to nothing. The heading
changes from the first log's name to the second's.

4. Look at the estimate in the first two seconds.

**Pass:** there is a dash, not a figure. It appears once the read has settled
and always reads *about*. Watch it for a while: it should narrow steadily rather
than swing between wildly different answers.

5. Press **Cancel**.

**Pass:** the button greys out and the card says it is stopping after the batch
in flight, *before* anything actually stops. Then check 2 takes over.

6. Let a clean ingest finish.

**Pass:** the card goes on its own. It must not be left standing over a window
that has finished working — and the same holds for a failed ingest, so repeat
with a file that is not a log at all and confirm the card goes before the error
appears.

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

## 8. The trace wrap can be turned off, and the choice is remembered

**Why:** this is the only setting the application persists, and persistence is
the half that cannot be seen by opening the window once. A preference that is
written but never read back looks correct until the next launch — and one that
is read but never written looks correct until the one after that.

1. Reconstruct a client whose trace has more than four activities, so the fold
   has something to fold. Note which node is ringed, if any.
2. **View → Wrap long traces**, or Alt+Z.

**Pass:** the trace redraws on a single row. It is wider than the window, so it
opens on its *first* activity with a scrollbar to pan rightwards along it —
not part-way through. Any ring is still on the same activity, at the position
that activity has moved to.

3. Switch to **View → Behaviour map**.

**Pass:** the wrap item is greyed out — a circle has no rows to fold — and still
shows its tick, so the remembered choice is visible rather than merely stored.

4. Close the application and start it again. Reconstruct the same client.

**Pass:** the trace is still unwrapped and the menu item still unticked. This is
the step that cannot be replaced by an automated check on this machine: the
suite substitutes the settings store precisely so it does *not* write to the
registry, so nothing but a real launch exercises the real one.

5. Turn it back on.

**Pass:** the trace folds again, and stays folded across a restart.

---

## 9. The evidence panel reads as the request, and can still prove itself

**Why:** the panel is where a finding stops being an assertion. It now shows the
request as the engine parsed it rather than the raw line, and that is only
acceptable while the raw line remains one keystroke away and identical to the
file it came from.

1. Reconstruct a client with an injection episode and click that node.

**Pass:** a table with a row per request — `Source`, `Time`, `Request`,
`Status`, `Size`. The payload is readable: `GET /product?id=1' OR '1'='1`, not
`%27+OR+%271%27%3D%271`. A served response stands out from refused ones. Values
read as values: a time of day rather than `1714564875`, `1.3 MB` rather than
`1400000.0`. The same goes for the client table on the left, whose `4xx` column
must show a percentage.

2. Click the `Size` heading twice to sort descending.

**Pass:** the largest response is on top — the request that got data out. Click
that row.

**Pass:** the detail beneath names the same `Source` as the highlighted row.
Sorting must never leave the detail describing a different request from the one
selected.

3. Read the `as logged` block in the detail and compare it with the file:

```powershell
Get-Content <log> | Select-Object -Index (<line> - 1)
```

They must be identical, character for character, including everything the table
leaves out. This is the check that makes summarising permissible at all.

4. **View → Decode URL escapes**, off.

**Pass:** requests are shown exactly as the log holds them, percent escapes and
all. Close the application and reopen it: the choice is as it was left.

5. Find or craft a request containing `%0A` and click its episode.

**Pass:** it is printed as `<U+000A>` and occupies **one row**. A decoded
newline would let whoever is being investigated draw over the row beneath — a
fabricated request, with a status of their choosing, in the table their case is
read from. Hover the row: the tooltip shows any `<` or `>` in the payload as
characters, never as markup.

---

## 10. The client filter finds one address without hiding the size of the case

**Why:** sorting answers *which client is worth opening*; it cannot answer
*where is 203.0.113.66*, which is the address an abuse report or a colleague
arrives with. On a case with tens of thousands of clients the only previous
answer was to scroll. The risk the filter introduces is the opposite one — a
narrowed list that no longer says how large the case really is.

1. Open a case with several thousand clients. Type part of an address —
   `203.0.113.` — into the box above the table.

**Pass:** the list narrows as you type, and the caption reads `N of TOTAL
clients match 203.0.113.` The total must stay on screen: a filtered list
captioned `9 clients` describes a case containing nine clients.

2. Type a **complete** address that exists in the case.

**Pass:** exactly one row. If several appear, the exact-match rule has been
lost — `203.0.3.9` is a substring of `203.0.3.90`, and an investigator copying
an address out of a ticket could open the wrong client and write it up.

3. Type an address that is not in the case at all.

**Pass:** the table is empty *and says why* — `No client matches 10.9.9.9.
1,200 in the case.` An empty table with no explanation reads as a broken tool.

4. Select a client and reconstruct it. Now type a filter that excludes it.

**Pass:** the canvas goes on showing the reconstruction you opened. Filtering
changes what is listed, not what is being read, and it must never start
analysing whoever happened to survive the filter. Clear the box: the row is
back, still selected.

5. With a filter applied, click a column heading to sort.

**Pass:** the same clients are on screen afterwards — sorting reorders what the
filter kept, it does not readmit what the filter excluded.

6. Open a different case.

**Pass:** the box is empty and the whole of the new case is listed. A filter
carried across would make a full case look nearly empty, and nothing on screen
would explain it.

---

## 11. Zooming behaves like zooming a picture

**Why:** canvas text used to be pinned to screen size so `fit()` could not
shrink it into a smudge. That produced the opposite fault — the geometry shrank
while the words did not, so on a 52-activity trace the captions went from 7
overlapping pairs at full zoom to 117 at 0.35, which is the zoom someone uses to
see the shape of a long session. Everything scales together now, so the check is
that nothing has quietly gone back to being exempt.

1. Reconstruct a client with a long, wrapped trace — 40 activities or more.
   Read the captions at the scale it opens at.

**Pass:** they are the size they always were. `fit()` stops at
`MIN_FIT_SCALE`, and captions are sized so that at exactly that scale they come
out at their written point size.

2. Zoom out with the wheel, well past the opening scale.

**Pass:** the whole drawing shrinks together — circles, arrows, words. Text gets
small, which is expected and is the honest half of the trade; what must **not**
happen is captions sliding into each other or across the circles. If two
captions touch at one zoom they will touch at every zoom, so one clean zoom
level is not evidence — check a far one.

3. Zoom back in past 1:1.

**Pass:** captions grow with the graph. A caption that stays the same size while
the circles grow is the old behaviour returning, and the overlap comes back with
it at the other end.

4. Compare against the exported HTML report of the same client.

**Pass:** the report's boxes are spaced from the same layout module, so a change
to canvas spacing shows up there as more room between boxes — never as boxes
overlapping or an SVG wider than the page.

## 12. A case that lost evidence says so, on every open

**Why:** the window used to say nothing at all. `case.ingest()` returned the
quarantine counts and the window discarded them, so a case that had lost 6.7% of
its lines drew exactly like one that had lost none — the failure
`ingest/quarantine.py` opens by calling this tool's worst. The CLI reported it
and the desktop application did not.

The automated tests can check that the strip appears. They cannot check that it
is legible, that it does not squeeze the client table, or — the point of the
whole feature — that it is still there for someone who never watched the ingest.

1. Take a log of a few thousand lines and corrupt a scattering of them: delete
   the timestamp from some, truncate the request on others. Ingest it through
   **Case → Ingest logs into a new case…**.

**Pass:** an amber strip appears beneath the menu bar naming how many lines were
refused and what share of the file that was. The share and the two counts
reconcile — divide them yourself.

2. Read the client table beside it.

**Pass:** all six columns are still visible. The strip takes height from the
window and must not take it from the table's width.

3. Narrow the window to around 1,000px.

**Pass:** the strip's text wraps onto a further line. Nothing is cut off
mid-word, and no scrollbar appears across the strip.

4. Click **Show the quarantined lines**.

**Pass:** the case's `quarantine` folder opens, holding `unparsed.jsonl` with
those lines and the reason each was refused.

5. Ingest a clean log into a second case.

**Pass:** no strip at all. Silence has to mean something, or the strip means
nothing.

**Not here, because it is automated:** that a dismissed strip comes back when
the case is opened again. That was on this list until it was pointed out that
the window can be driven without a person —
`test_a_dismissed_strip_returns_when_the_case_is_opened_again` loads a damaged
case, dismisses the strip, loads a clean one, and loads the damaged one back.
Making the strip remember having been dismissed fails that test and no other.

## 13. A log the parser could not read interrupts

**Why:** damage inside a log is a strip. A log that produced *no* events is a
different thing — nothing from it is in the case, and the window behind shows a
short client list, which is exactly what a quiet day of traffic looks like. With
only a strip there is nothing on screen separating a working case from a broken
ingest.

**Build this case at the command line, not in the window.** The window never
passes a format — `_ingest_new_case` always lets one be detected — so it cannot
produce this state itself, and detection would refuse the second file up front
rather than quarantine it. `--format` is what turns that refusal into silence,
and the CLI is the only place it can be given:

```bash
logarc ingest access.log notes.txt --case ./case-dead --format apache-combined
```

where `notes.txt` is any file that is not an access log. That the case has to
arrive from elsewhere is the realistic shape of it anyway: this is what an
investigator opens when a colleague did the ingest.

1. Open `case-dead` in the window through **Case → Open case…**.

**Pass:** a dialog appears. It names the file, the format it was read as, and
how many of its lines were refused — the format is the part that tells you the
parser was wrong rather than the log being empty.

2. Dismiss it.

**Pass:** the amber strip is behind it, so the case still says so once the
dialog is gone.

3. Read the client list.

**Pass:** it holds only the good log's clients. The case is genuinely short of
what was handed to it, and both the dialog and the strip said so before you
worked that out for yourself.

4. Now ingest the same two files through the window, which cannot name a
   format.

**Pass:** ingest refuses the second file outright rather than quarantining it,
and says which formats it accepts. The refusal and this dialog are two halves of
the same guard — one for the case where a format was guessed, one for the case
where it was asserted — and neither silently swallows a file.

## 14. Several cases can be taken off the list in one pass

**Why:** the only visible control in the chooser was `Forget these`, and it wiped
the whole list and shut the dialog — so a reader tidying ten entries reopened it
ten times, and the button's name described the selection while its behaviour
ignored it. Removing one entry worked, and was hidden behind a right-click.

What the suite cannot judge: whether the star reads as *pinned* rather than as a
rating, and whether the rows still look right after several redraws.

1. Open **Case → Recently opened…** with five or more entries. Ctrl-click three.

**Pass:** three rows highlight. **Open** greys out — it has no answer for three.

2. Press **Forget these**.

**Pass:** those three go, the other rows stay, and *the dialog is still open*.
The rows are the same height they were before the redraw.

3. Ctrl-click two more and press it again, without reopening anything.

**Pass:** they go too. This is the pass that was impossible before.

4. Right-click one row of a multi-selection.

**Pass:** the rest stay highlighted. Right-click a row *outside* the selection
and it becomes the only one selected, as in any file list.

5. Look at a pinned row.

**Pass:** the mark is a star in the interface blue, not a red pushpin. Red in
this application means something is wrong with the evidence, and a pinned case
is not that.

6. Press **Ctrl+A**, then **Forget these**. Close the window and open it again.

**Pass:** the chooser does not appear at all — there is nothing to offer. Check
`HKCU\Software\logarc` with `regedit`: the recent-cases value is **gone**, not
present and empty. That distinction is the whole promise of this control.

---

## 15. Activities can be rearranged, and the arrangement kept

**Why:** the arrows and the selection ring were drawn once from the layout and
knew nothing about a node that had moved since. The suite checks that they
follow, that the scene makes room, and that the number on an arrow gives way
when the arrow gets too short to carry it.

What the suite cannot judge: whether the drag *feels* attached to the cursor,
and whether the lit arrows read as "this is what is moving" rather than as a
rendering fault. One mouse-move event of a drag measured 0.30 ms on a 50-node
trace and 0.34 ms on 600, against a 16 ms frame — so if it feels heavy, the
cause is somewhere else and worth finding.

1. Open a case, pick a client, and drag an activity across the canvas.

**Pass:** the circle stays under the cursor. Its caption comes with it. The
arrows either side stretch to follow rather than lagging a frame behind, and
they are the interface blue while the button is down. The cursor is the
four-way arrow, not the closed hand — the closed hand means panning.

2. Let go, then drag on empty ground.

**Pass:** the arrows go grey again, at the weights their counts earned — a
heavier transition is still heavier. The canvas pans as it always did.

3. Drag one activity almost on top of the one it points at.

**Pass:** the arrow between them stays visible as an arrow. The number on it
disappears rather than covering it, and comes back when they are pulled apart.

4. Press **Ctrl+Z**.

**Pass:** that activity goes back exactly where it was, arrows and ring with
it. Press it again with nothing left to undo: the menu entry is greyed out and
nothing moves.

5. Move three activities, then **View → Save this arrangement**. Switch to
   **Behaviour map** and back to **Trace**.

**Pass:** the three are where you left them. The behaviour map is laid out
normally — its arrangement is its own.

6. Close the application and open the same case and client again.

**Pass:** the arrangement is still there.

7. **View → Reset layout**, then close and reopen the case.

**Pass:** the computed layout, both times. The saved arrangement is gone, not
merely overridden — reset that only moved the nodes would let it come back on
the next open, which reads as the reset having failed.

8. Drag an activity far off the edge of the graph, then pan after it.

**Pass:** you can follow it; the scene made room. Drag it back and let go: the
scene settles, and **View → Fit to window** frames the graph rather than the
empty ground it was dragged across.

---

## 16. A case can be read over one stretch of time

**Why:** the suite checks that both halves narrow together and that the numbers
agree. What it cannot judge is whether the band is worth having — on the
synthetic log it is nearly flat, because generated traffic is uniform, and the
whole argument for drawing it rests on a real log not being.

Measured, so there is something to compare against: opening a case 1.1 s at
200 k events and 1.3 s at 3 million; applying a range 0.35 s and 0.44 s; going
back to the whole case 0.90 s and 1.08 s. The last of those is over a second,
and is the one to watch.

1. Open a case and look at the band above the panels.

**Pass:** it is filled end to end, and on a real log it has shape — quiet
nights, busy hours. If it is a flat wall, say so: that is the finding.

2. Drag a stretch out of the middle of the band.

**Pass:** the fields beneath it change to match. The client list shrinks to who
was active then. The line on the right says both counts.

3. Pick a client and compare its row against the heading above the graph.

**Pass:** the same number of requests in both. This is the check the whole
feature was shaped around; if these two ever disagree, stop and report it.

4. Look at an activity that started before your range began.

**Pass:** it reports the requests inside the range, not all of them.

5. Type a range into the fields instead.

**Pass:** the highlight on the band moves to match. One range, two controls.

6. Narrow to a stretch when nobody was active.

**Pass:** the list is empty and says *No client was active …* with the times.
Not a blank panel, and not zero of nine thousand.

7. Export an HTML report while a range is set, and another with **Whole case**.

**Pass:** the filtered one carries a **Time range** card; the other does not.
Open both and search for the same activity id: they must not share one.

8. Press **Whole case**.

**Pass:** the full client list is back, and the graph is the whole reconstruction
again.

9. Pick a client and watch the band.

**Pass:** its ends become that client's first and last request, and the bars are
that client's own. A client that worked for an hour fills the band. Compare the
bar heights against the graph: a burst in the band should be an activity in the
trace.

10. Press the row of the client you are already on.

**Pass:** the highlight goes, the graph goes back to waiting, and the band goes
back to the whole case. Nothing on screen still names that client — check the
status bar at the bottom too. Press a different row: it opens that client as
usual.

11. Narrow to a stretch that client was not there for.

**Pass:** the graph empties and the band goes back to the whole case — it must
not go on drawing a client no longer on screen.

12. **View → Show the traffic band**, to turn the drawing off.

**Pass:** the bars go and the date fields stay. The graph gains the height —
measured at 62 pixels. Set a range with the fields: it still narrows both halves.

13. Close the application and open it again.

**Pass:** the band is still off. Turn it back on and it draws as before.

---

## 17. A format you write yourself reads a log the presets cannot

Everything here is automated except the one thing that matters — that the
preview is legible while you are typing, which is the whole reason to have it.

1. Make a log nothing built in can read:

```bash
printf '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET /.env HTTP/1.1"|404|0\n' > piped.log
```

2. Open the application. **Case → Log formats…**

**Pass:** the list is grouped — *Built in* above, *Saved by you* below — with
*New format…* at the top. Selecting `apache-combined` fills the fields and
greys them out; Save and Delete are unavailable.

3. Paste the line from `piped.log` into *A line from your log*, while
   `apache-combined` is still selected.

**Pass:** it says the directive does not read that line. The table is empty.

4. Click *New format…*. Name it `piped`. Type the directive one character at a
   time: `%h|%t|"%r"|%>s|%b`

**Pass:** the message changes as you type, and settles on *Read this line, and
found 7 of 11 fields in it*. Every one of the eleven fields is in sight without
scrolling — Client, When, Method, Path, Query, Protocol, Status, Bytes,
Referer, User agent, Host — with the four the format does not carry shown
empty rather than missing.

5. Save. Close the dialog. **Case → Ingest logs into a new case…**, choose
   `piped.log`, and in the format question choose `piped`.

**Pass:** the case opens with one client in it, not an empty one.

6. Go back to **Log formats…**, select `piped`, add `|%{Referer}i` to the end
   of the directive, save, and open the case again.

**Pass:** an amber strip appears saying the format has changed since the case
was made, **and the case still shows its client**. The strip names both
directives. Dismissing it does not dismiss the quarantine strip if one is up.

---

## 18. A JSON log's mapping is proposed, not demanded

1. Make a nested JSON log:

```bash
python - <<'PY'
import json, pathlib
rows = [{"@timestamp": f"2024-05-01T09:00:{n:02d}+00:00",
         "client": {"ip": "203.0.113.77"},
         "http": {"request": {"method": "GET"}, "response": {"status_code": 404}},
         "url": f"/admin/{n}.php", "user_agent": {"original": "curl/8.4.0"}}
        for n in range(40)]
pathlib.Path("ecs.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
PY
```

2. **Case → Log formats… → New JSON format…** Paste one line into *A line from
   your log*, then press **Guess from the line above**.

**Pass:** the left table fills in — `timestamp` → `@timestamp`, `client_ip` →
`client.ip`, `method` → `http.request.method`, `user_agent` →
`user_agent.original`. The right table beside it shows what those read out of
the line. Both tables are fully visible without scrolling.

3. Clear the `client_ip` row and type `client.address` instead.

**Pass:** the message changes to say nothing was read, and **names the keys the
line actually has** — that is the answer worth having here, and it is different
from the one a directive gets.

4. Put `client.ip` back, name it `ecs`, save, and ingest `ecs.jsonl` with it.

**Pass:** 40 events, none quarantined. `logarc formats show ecs` prints the
mapping.

---

## 19. An IIS log needs almost no configuring

1. Take a real IIS log, or write one:

```bash
python - <<'PY'
import pathlib
head = ["#Software: Microsoft Internet Information Services 10.0", "#Version: 1.0",
        "#Date: 2024-05-01 09:00:45",
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip"
        " cs(User-Agent) sc-status sc-bytes time-taken"]
rows = [f"2024-05-01 09:00:{n:02d} 10.0.0.1 GET /admin/{n}.php - 80 203.0.113.77"
        f" curl/8.4.0 404 0 15" for n in range(40)]
pathlib.Path("u_ex240501.log").write_text("\n".join(head + rows) + "\n")
PY
```

2. **Case → Log formats… → New table format…** Paste the four header lines and
   one row, then press **Guess from the line above**.

**Pass:** the left table fills in with W3C names — `timestamp` → `date+time`,
`client_ip` → `c-ip`, `method` → `cs-method`, `status` → `sc-status`. The right
table shows what those read out of the row, and the columns nobody mapped
(`s-ip`, `s-port`, `time-taken`) appear under it as extras.

3. Name it `iis`, save, and ingest `u_ex240501.log` with it.

**Pass:** 40 events and **0 quarantined** — the four `#` directives are the
log's own bookkeeping, not lines that failed. No amber strip appears.

4. `logarc formats show iis`

**Pass:** Columns reads **from the log**, not a frozen list. The case's
`case.json`, though, names the columns that were actually in this file.

---

## 20. A log nothing else can read

1. Write one that is none of the four shapes — syslog around a proxy:

```bash
printf '2024 May  1 09:00:%02d gw01 proxy[1234]: client=203.0.113.77 method=GET url=/admin/%d.php status=404\n' $(seq 0 39 | sed 's/.*/& &/') > proxy.log
```

2. **Case → Log formats… → New pattern format…** Paste one line, set *Time
   format* to `%Y %b %d %H:%M:%S`, and write:

```
^(?P<timestamp>\d{4} \w+\s+\d+ \d\d:\d\d:\d\d) \S+ \S+: client=(?P<client_ip>\S+) method=(?P<method>\S+) url=(?P<path>\S+) status=(?P<status>\d+)
```

**Pass:** the table fills in as you type the last group. There is no mapping
table on this screen — the group names are the mapping.

3. Clear the *Time format* box.

**Pass:** it says the pattern does not read the line, because `May  1 …` is
neither ISO nor a number. Put the format back.

4. Change *Time format* to `%b %d %H:%M:%S` — no year.

**Pass:** it is refused, and the message says every event would be dated 1900.

5. Restore the year, save as `gw-proxy`, and ingest `proxy.log` with it.

**Pass:** 40 events, none quarantined, all dated 2024.

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
| 8 | Wrap toggles, greys out off-view, and survives a restart | | |
| 9 | Evidence reads as the request; raw line matches the file byte for byte | | |
| 10 | Filter finds one address, states the total, survives a sort | | |
| 11 | Zoom scales the whole drawing; captions never touch at any zoom | | |
| 12 | A damaged case reports its unparsed lines legibly, without squeezing the table | | |
| 13 | A log that produced no events interrupts, and names the format | | |
| 14 | Several cases forgotten in one pass; Ctrl+A removes the key itself | | |
| 15 | Activities drag smoothly; undo, save and reset behave | | |
| 16 | A time range narrows both halves; the band can be turned off | | |
| 17 | A written format reads a log the presets cannot; the preview keeps up | | |
| 18 | A JSON log's mapping is guessed, correctable, and says what the keys are | | |
| 19 | An IIS log reads from its own header; its directives are not quarantined | | |
| 20 | A pattern reads a syslog-wrapped log; a year-less time format is refused | | |

Version tested: ______  ·  Date: ______  ·  Machine: ______
