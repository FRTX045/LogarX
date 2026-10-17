# GUI text colors

Text color identifies a role, not a verdict about the traffic. Labels, values,
severity names, and status messages remain readable without recognizing a hue.
Normal prose and requests use neutral ink; supporting descriptions and source
references use muted ink. Font sizes and the dark document surfaces stay as they
are. Rank numbers and format-preview field labels use muted ink because they are
structure beside the values, rather than the evidence to read first.

| Role | Where it appears | Reason |
| --- | --- | --- |
| Teal: logged identity | IP columns in the client list, investigation queues and Who else; selected-IP headings; client/host evidence fields; site-host input; corresponding format-preview values | Helps the reader locate **who** or **which host** a record describes. It does not mean the address is trusted or clickable. |
| Soft violet: time | First/last-seen columns, request times, example timestamps, activity time ranges, timeline endpoints, time-filter date fields, recent-case open times, format-preview times and ingest time remaining | Separates **when** from counts, paths and source references. Durations share the time role. |
| Amber: caution | Positive flagged-request counts, provisional scan messages, cancellation state and notice headlines; optional CRS unavailable heading | Calls for review of a warning or limitation. A flagged count does not establish compromise. |
| Rose: evidence or operation error | Unreadable/changed source warnings, failed jobs/searches and invalid format previews | Distinguishes a problem with the tool's input or operation from an ordinary finding. An empty format form is an instruction, not an error. |
| Severity hues | Activity title and severity chip in the evidence panel | These already represent a classified finding. Text versions of the graph's hues have higher contrast where necessary; the node fills and legend swatches keep their existing colors. |
| Blue: interaction or active work | Links, selected tabs, active status messages, ingest state/progress and running CRS heading | Helps locate navigation and the operation currently running. Disabled controls retain their disabled color. |

HTTP status codes retain their existing neutral served/refused emphasis: a 200
response is not proof that an attack succeeded, and a green success cue would be
misleading. Request paths, payloads, raw log lines, percentages, counts and generic
finding titles receive no arbitrary syntax or severity coloring. Unusual activity
does not acquire a severity color merely for differing from other clients.

The review covered the main window and status bar, client and investigation
lists, finding cards and context, reconstruction captions and legend, request
evidence and collapsible details, timeline and filters, warning and arrangement
bars, ingest/CRS progress, recent cases, Who else, site-host input, format editing
and previews, preferences, menus, window controls and message dialogs. Ordinary
dialog explanations, preferences, menu items, raw logs, graph captions and resize
controls keep their existing neutral or already meaningful treatment. The
arrangement bar already has a marker for unsaved work.

All role colors come from `logarc.style.Theme`, including light-theme equivalents.
Contrast checks require at least 4.5:1 on document, raised, alternating and selected
surfaces for role and severity text. Source text continues to be inserted literally
or HTML-escaped; applying color never changes the evidence or detection rules.
