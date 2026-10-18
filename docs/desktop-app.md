# The desktop application

```bash
logarc-gui
```

Everything here drives the same `logarc.case` and `logarc.analysis` functions the
command line drives. The window contains no analysis of its own — what it adds is
a way to read a reconstruction, click a node, and see the log lines behind it.

Two results it can produce that the CLI cannot, and both are deliberate:
exporting the canvas as a **PNG**, which is a picture rather than a
serialisation of the reconstruction, and narrowing a reconstruction to a
**stretch of time**. Both are described below.

Window state — preferences, saved arrangements, the recent-case list — is the
window's own and has no command-line equivalent by nature.

Interface text starts at 14 pt, evidence text at 13 pt, and small interface
captions at 12 pt. Larger system font choices are preserved. Graph captions and
transition labels are slightly larger too, opening at about 11.6 pt or more at
the default minimum zoom; zooming scales the graph and its text together.
Preferences uses a scrolling page when its explanations need more room, with
the confirmation buttons always visible below it.

Scrollbars have 20 px tracks, brighter handles, and a minimum handle length of
42 px. The dividers between panels use 5 px lines with a 1 px margin on each
side and highlight blue when hovered.

On WSL, the menu strip has 34 × 28 px minimize, maximize/restore, and close
buttons with 15 px symbols. Drag its empty space to move the window,
double-click to maximize or restore, and drag an edge or corner to resize.
Graph fullscreen hides the strip and restores the previous window state when
leaving fullscreen.

On WSL, Qt keeps its normal display-backend selection. Returning from graph
fullscreen to a maximized Wayland window briefly hides and shows that same
window, giving it a fresh display surface. This avoids the fatal `0 × 0`
configuration reported in [WSLg issue #1428](https://github.com/microsoft/wslg/issues/1428).
Forcing X11 introduced incorrect borderless-window bounds and cursor hit positions
([WSLg issue #1015](https://github.com/microsoft/wslg/issues/1015)), so the launcher
does not force that backend. Explicit `QT_QPA_PLATFORM` settings remain respected.

The WSL launcher requests a 32 px cursor. This default applies to this application
and respects existing environment settings. For a larger cursor, launch with
`XCURSOR_SIZE=48 logarc-gui`.

---

## The menus

| Menu | Holds |
|---|---|
| **Case** | Open case… (Ctrl+O) · Recently opened… (Ctrl+Shift+O) · Ingest logs into a new case… · Log formats… · Exit |
| **Edit** | Undo node move (Ctrl+Z) · Save this arrangement (Ctrl+S) · Reset layout (Ctrl+Shift+R) · Preferences… (Ctrl+,) |
| **View** | Trace (chronological) · Behaviour map · Fit to window · Full screen |
| **Export** | HTML report… · JSON graph… · PNG image… |

`Edit` rather than `View` for the arrangement entries, because Ctrl+Z is the
first thing anyone looks for there.

Several behaviours that read like menu items are **preferences**, under
**Edit → Preferences…**: *Wrap long traces*, *Outline each session*, *Show the
traffic band*, and *Reopen the last case on start*. They are remembered between
launches.

---

## Opening a case

![Choosing from the cases opened before](images/screenshot-case-chooser.png)

Opening the window offers the cases you have worked on before.
**Case → Recently opened…** brings that list back at any time, and the
*Reopen the last case on start* preference skips it and goes straight to the one
you were in.

Ctrl-click chooses several rows and **Forget these** takes them off the list,
which stays open — so tidying a list of ten is one pass rather than ten openings.
Right-click a row to pin it to the top, rename it in the list, or show its
folder. A rename is a label here only: `case.json` keeps the case id that every
exported report prints.

**That list is kept on the machine you are working at.** It records which cases
were opened here — their folders, when, and how much was in them — under
`HKCU\Software\logarc` on Windows, beside the view preferences. That is a record
of what was investigated, not merely of how the window looked, so it has to be
removable: **Ctrl+A** then **Forget these** takes every entry, and an emptied
list removes the registry key rather than storing an empty one in it.

---

## Reading a case

![The case as it opens: every client, and the traffic band above](images/screenshot-case.png)

The table lists the busiest clients in the case, sortable by every column. The
`4xx` share is the one worth sorting by first: a client probing for things that
are not there looks exactly like a high refusal rate.

Pick a client and the reconstruction runs on a worker thread. Long work can be
cancelled. A running ingest says how far it has got — the log being read, a real
percentage of the bytes, the lines parsed so far and the rate — because reading a
gigabyte takes minutes and a busy tool is otherwise indistinguishable from a hung
one. The estimate of what is left is withheld until the read has settled and
always reads *about*: the first seconds are the least representative, and a
confident figure drawn from them is the kind of number this tool is built not to
print. **A cancelled ingest leaves the case un-finalised**, so a partial read can
never be analysed as if it were complete.

**Pressing the client you are on lets go of it.** The graph goes back to waiting
and the band goes back to the whole case. Pressing a different row moves to that
client as it always did.

### Searching the case

The box above the list searches the whole case, not only the clients the table
holds. An address finds a client as it always did: part of one finds every
client whose address contains it, a whole one only that client, and several
find any of them.

It also takes the evidence box's filters, and finds the clients that sent a
matching request:

| Filter | Finds |
|---|---|
| `status:404`, `path:/admin`, `method:POST`, any text | clients with at least one matching request, most matches first, with a **Match** column saying how many |
| `ip:10.0` | clients whose address contains it |
| `activity:enumeration` | clients the Where to start scan saw that activity on, by category or by part of a rule's name. Quote a value with a space in it: `activity:"path traversal"` |
| `after:02:58`, `before:2026-03-09T03:00` | move the range above the list, and leave the box. A time of day is read on the range's first day |

The line above the list gives both numbers:
`8 of 52 clients sent a request matching path:/admin · 123 requests`. While a search
runs, no rows are shown, so nothing on screen can be read as its answer.

A time moves the range once it is a chip: after a space, after Enter, or chosen
from the list. So a pause while typing `after:2026-03-09` on the way to a time
on that day does not move the range to midnight. Whatever else is in the box is
searched again over the new range.

`activity:` is answered by the Where to start scan. Until the scan finishes the
line above the list says so, and the list fills in by itself when it does.

Click the box to see what it searches by. Type `status:`, `method:` or
`activity:` to see the values in the range, with how many clients, and for a
status or a method how many requests, carry each.

**A client opened from a search of its requests is read the same way.** Its
evidence is filtered by those filters, and the first activity holding a match
opens. Addresses, activities and times chose the client and the range, so they
are not carried over.

---

## The two views

![The trace, with the evidence behind the selected activity](images/screenshot-trace.png)

**Trace** is chronological: one node per episode, arrows in time order. It reads
as a sequence.

Long chains wrap onto further rows, alternating direction, because a trace drawn
on one line is as wide as it is long and shrinks to an unreadable smudge when
fitted to the window. The *Wrap long traces* preference turns the fold off when
the straight timeline is worth more than legible captions; the graph is then
panned rather than fitted, opening on its first activity.

Each session sits in a box of its own, labelled with its number, how many
activities it holds and when it ran, such as `Session 2 of 69 · 2 activities ·
09 Mar 01:55–02:26`. That gives the session count in the header something on the
canvas to point to. Rest the pointer on a label to see what makes a session:
no pause inside it longer than 30 minutes, the same user agent throughout, and
8 hours at most. A box follows its activities when they are dragged. The
*Outline each session* preference turns the boxes off, and nothing moves when
it does.

![The behaviour map: 557 requests folded into five activities](images/screenshot-behaviour.png)

**Behaviour map** is aggregated: one node per activity type, arrows weighted by
how often that transition was observed. It reads as a habit. The `x23` on an
arrow is the thing the trace cannot show — that the client went round that loop
twenty-three times.

Neither view links across a session boundary. A gap long enough to end a session
is a break in the story, not a transition within it.

**View → Full screen** gives the graph the whole window.

![The graph alone](images/screenshot-graph.png)

---

## The evidence

![The raw lines behind a SQL injection episode](images/screenshot-evidence.png)

The panel on the right is what the selected node was built from, a row per
request. Sort it by size to find the one that got data out, or by status to find
what was served rather than refused.

Payloads are decoded, so `' OR '1'='1` reads as the tautology it is instead of
`%27+OR+%271%27%3D%271`. The pane beneath holds the selected request in full,
including the source line exactly as the log holds it — every finding traces back
to a line.

### Filtering the lines

The box above the table keeps the lines of the selected activity that match what
you type. A word keeps the lines whose request, path and query, holds it, as
logged or decoded. A filter narrows by one field:

| Filter | Keeps |
|---|---|
| `status:404` | that response code; `status:4xx` keeps the whole class |
| `path:/admin` | paths containing it; quote a value with a space, `path:"/my files"` |
| `method:POST` | that method |
| `after:02:58`, `before:2026-03-09T03:00` | requests at or after, or before, that time. A time of day is read on the activity's own day |

Two of the same filter keep either one. Different filters and words must all
hold. A finished filter becomes a chip, and Backspace or its × takes it off.
Anything the box cannot read as a filter is searched as text, so a typo narrows
the table rather than being quietly ignored.

Click the box to see what it filters by. Type `status:` or `method:` to see the
values this activity holds, with how many lines carry each.

The filter searches every line of the activity, not only the 2,000 the table
loads, and the line above the table says what it did:
`Filtered · 31 of 106 lines match status:304`. When nothing matches, the table
says *No results found* and offers to clear the filter.

The canvas fades every activity with no matching line, so the box also answers
"which of these had a 500?" before you pick one. The filter stays while you
move between activities and between the two views. Opening another client
starts without one, unless a search of the case found it by its requests: see
*Searching the case* above.

---

## Moving things about

Activities can be dragged where you want them. Their arrows and the selection
ring come along, **Ctrl+Z** takes the last move back, and **Edit → Save this
arrangement** keeps it for the next time this client is opened.
**Edit → Reset layout** returns to the computed one and forgets what was saved.

**A saved arrangement is a record of what you were reading.** It is filed under
the case, the client, the view and the wrap setting, and the coordinates it holds
are keyed by activity id — which for a trace carries the client's address in
plain text. So saving an arrangement writes down which client of which case you
were reading, in the same place and with the same consequences as the recent-case
list. **Reset layout** removes the one for the graph in front of you.

---

## A stretch of time

The band above the panels shows where the traffic sits — the day-night rhythm,
and the bursts standing out of it — and a stretch is dragged out of it or typed
into the two fields beside it.

Both halves of the window narrow together: the client list shows only who was
active in that stretch, with that stretch's own counts, and the graph is
*reconstructed* from those requests rather than drawn with parts hidden. An
activity that straddles the edge reports what is inside it, not what it would
have been over the whole case.

Because that is a different answer, it is given a different name: identifiers
carry the range, so `100.67.0.86@20240502T012500-20240502T020000#1/1` can never
be mistaken for the whole-case `100.67.0.86#1/1` in a folder holding both
reports. Without a range nothing changes — every case and report made before this
existed still reads exactly as it did. **Whole case** goes back.

**The band follows whoever is being read.** Before a client is picked it draws the
whole case. Pick one and it becomes that client's own history, across that
client's own life — first request to last — so a client alive for ninety minutes
fills the band instead of being a hairline in the middle of two days. Letting go
of the client hands the case back.

The band is optional: the *Show the traffic band* preference turns the drawing
off and gives its pixels back to the graph. Only the picture goes — the fields
and **Whole case** stay, because they are the precise control and the one to fall
back on for a stretch too narrow to drag onto.

---

## Log formats

![The format library: fourteen built in, and one of the reader's own](images/screenshot-log-formats.png)

**Case → Log formats…** holds the formats that ship above and yours below, and
neither can be confused for the other: a built-in is readable and not editable,
because registration order is preference order and an edited copy of
`apache-combined` would never be reached.

![Writing a format, with a pasted line read back field by field](images/screenshot-format-editor.png)

Paste one line from your log and the rule is tried against it as you type. Here a
directive with a forwarded-for header and a duration reads into nine of the
eleven canonical fields plus two more besides — and those two are usually the
whole reason a site has a format of its own. A rule that reads nothing says so.

The same four kinds the CLI offers are here: a directive for a text log, a field
mapping for a JSON one, columns for a table, and a regular expression for
anything else.

---

## When a case is incomplete

A case that could not read all of its logs says so, every time it is opened — an
amber strip naming how many lines were refused and what share of the file that
was. When a whole log produced *no* events, that is not damage but the wrong
parser, so it interrupts instead, naming the file and the format it was read as;
that name is the part that separates a wrong parser from a log that genuinely
holds nothing.

The counts come from the case manifest rather than from having watched the
ingest, so they are still there when a colleague opens the case a week later.
Nothing is shown when nothing was quarantined — silence means the case holds
everything its logs did.

A case whose format has been edited or deleted since it was ingested says that
too. The case itself is unaffected: it records the format *definition* it was
read with, not the name.

---

## How it is checked

The window is verified by hand against
[manual-test-plan.md](manual-test-plan.md) — whether the node you clicked is the
one whose evidence appeared is a judgement about what a person sees.

The decisions that determine whether a graph *misinforms* are kept out of Qt, in
`logarc.style`, and tested directly. A finding is the same colour in the window
and in the exported report because both read the same table.
