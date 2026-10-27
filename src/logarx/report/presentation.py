"""Offline report presentation. Theme selection uses native radios, not scripts."""

from typing import Final

from logarx.style import DARK, LIGHT, Theme
from logarx.typography import MONO_FAMILIES, UI_FAMILIES


def _palette(theme: Theme) -> str:
    return ";".join(
        f"--{name}:{value}"
        for name, value in {
            "page": theme.chrome,
            "surface": theme.surface,
            "raised": theme.raised,
            "stripe": theme.stripe,
            "line": theme.line,
            "edge": theme.edge,
            "ink": theme.ink,
            "muted": theme.muted,
            "accent": theme.accent,
            "identity": theme.identity,
            "timestamp": theme.timestamp,
            "warning": theme.warning,
            "edge-ink": theme.edge_ink,
            "grid": theme.grid_dot,
            "outline": theme.ink,
        }.items()
    )


def _fonts(families: tuple[str, ...]) -> str:
    return ",".join(f'"{family}"' if " " in family else family for family in families)


STYLE: Final = (
    f".report {{{_palette(DARK)};color-scheme:dark;"
    f"--ui:{_fonts(UI_FAMILIES)};--mono:{_fonts(MONO_FAMILIES)}}}\n"
    f"#theme-light:checked ~ .report {{{_palette(LIGHT)};color-scheme:light}}\n"
    + """
* { box-sizing: border-box; }
body { margin: 0; }
.report { min-height: 100vh; background: var(--page); color: var(--ink);
  font: 16px/1.55 var(--ui); padding: 0 32px 36px; }
main, .topbar { max-width: 1240px; margin: 0 auto; }
.topbar { display: flex; justify-content: space-between; align-items: center;
  gap: 20px; padding: 22px 0; border-bottom: 1px solid var(--edge); }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700;
  font-size: 21px; letter-spacing: -.5px; }
.brand svg { width: 28px; height: 28px; color: var(--accent); }
.brand span { color: var(--muted); font-size: 13px; font-weight: 400;
  letter-spacing: 0; border-left: 1px solid var(--edge); padding-left: 12px;
  margin-left: 6px; }
.theme-choice { position: absolute; width: 1px; height: 1px; padding: 0;
  overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.theme-switch { display: inline-flex; border: 1px solid var(--edge);
  border-radius: 8px; padding: 3px; gap: 3px; background: var(--surface); }
.theme-switch label { cursor: pointer; padding: 6px 14px; border-radius: 5px;
  color: var(--muted); font-size: 14px; }
#theme-dark:checked ~ .report label[for="theme-dark"],
#theme-light:checked ~ .report label[for="theme-light"] {
  background: var(--raised); color: var(--ink); box-shadow: inset 0 0 0 1px var(--edge); }
#theme-dark:focus-visible ~ .report label[for="theme-dark"],
#theme-light:focus-visible ~ .report label[for="theme-light"],
a:focus-visible, summary:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 3px; }
.report-heading { padding: 36px 0 24px; }
.eyebrow { color: var(--muted); font-size: 13px; font-weight: 600;
  letter-spacing: .09em; text-transform: uppercase; margin: 0 0 8px; }
h1 { font-size: clamp(26px, 4vw, 36px); line-height: 1.25; font-weight: 600;
  letter-spacing: -.6px; margin: 0; overflow-wrap: anywhere; }
h1 .client { color: var(--identity); }
h2 { font-size: 19px; font-weight: 600; margin: 0; letter-spacing: -.2px; }
p { margin: 0; }
.subtitle { color: var(--muted); margin-top: 10px; font-size: 14px; }
nav { display: flex; flex-wrap: wrap; gap: 6px 22px; margin-bottom: 24px; }
a { color: var(--accent); text-underline-offset: 4px; }
nav a { font-size: 14px; text-decoration: none; }
nav a:hover { text-decoration: underline; }
.cards { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px; margin-bottom: 34px; }
.card { background: var(--surface); border: 1px solid var(--line);
  border-radius: 9px; padding: 18px 20px; min-width: 0; }
.card-label { color: var(--muted); font-size: 13px; margin-bottom: 6px; }
.card-value { font-size: 24px; line-height: 1.35; font-weight: 600;
  font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.card-value .context { font-size: 16px; }
section { margin: 0 0 30px; scroll-margin-top: 24px; }
.section-heading { display: flex; flex-wrap: wrap; align-items: baseline;
  gap: 6px 16px; margin-bottom: 12px; }
.section-heading p { color: var(--muted); font-size: 13px; }
.panel, .table-wrap { background: var(--surface); border: 1px solid var(--edge);
  border-radius: 10px; overflow: hidden; }
.graph-scroll { overflow: auto; max-height: 680px; padding: 24px;
  background-image: radial-gradient(circle, var(--grid) .7px, transparent 1px);
  background-size: 20px 20px; }
.graph-scroll > svg { display: block; margin: 0 auto; max-width: none; }
.empty { color: var(--muted); padding: 28px; text-align: center; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 14px 16px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { background: var(--raised); font-size: 12px; font-weight: 600;
  color: var(--muted); white-space: nowrap; }
tbody tr:nth-child(even) { background: var(--stripe); }
tr:last-child td { border-bottom: none; }
td { overflow-wrap: anywhere; }
.activities { min-width: 1000px; }
.activities td:nth-child(2) { min-width: 180px; }
.activities td:nth-child(7), .activities td:nth-child(8) { min-width: 160px; max-width: 260px; }
.mono { font-family: var(--mono); }
.time { color: var(--timestamp); white-space: nowrap; }
.small { font-size: 12px; }
.muted { color: var(--muted); font-size: 13px; }
.warn { color: var(--warning); font-size: 14px; font-weight: 600; margin-top: 6px; }
.pill { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; }
.pill i, .key i { display: inline-block; width: 9px; height: 9px;
  border-radius: 50%; flex-shrink: 0; }
.swatch { box-shadow: 0 0 0 1px var(--edge); }
.legend { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px;
  border-top: 1px solid var(--line); padding: 14px 20px;
  color: var(--muted); font-size: 12px; }
.legend b { color: var(--ink); font-weight: 600; }
.key { display: inline-flex; align-items: center; gap: 6px; }
.key i.outline { width: 14px; height: 14px; background: var(--raised);
  border: 2px solid var(--outline); }
.key i.outline.dashed { border-style: dashed; }
.session-box { fill: var(--surface); stroke: var(--edge); stroke-width: 1; }
.session-accent { fill: var(--accent); opacity: .05; }
.session-title { font: 600 18px var(--ui); fill: var(--ink); }
.session-meta { font: 13px var(--ui); fill: var(--timestamp); }
.activity-node { stroke: var(--outline); }
.node-title { font: 600 15px var(--ui); fill: var(--ink); }
.node-meta { font: 13px var(--ui); fill: var(--muted); }
.caption-ground { fill: var(--surface); }
.edge { stroke: var(--edge-ink); }
.arrow-head { fill: var(--edge-ink); }
.edge-label { font: 12px var(--mono); fill: var(--muted);
  paint-order: stroke; stroke: var(--surface); stroke-width: 6px; stroke-linejoin: round; }
details { margin-top: 16px; background: var(--surface); border: 1px solid var(--edge);
  border-radius: 10px; overflow: hidden; }
summary { cursor: pointer; padding: 16px 20px; font-weight: 600; }
summary h2 { display: inline; font-size: 16px; }
summary::marker { color: var(--muted); }
details .table-wrap { border: 0; border-radius: 0; }
pre { background: var(--raised); color: var(--ink); padding: 16px; margin: 0;
  overflow: auto; font: 12px/1.6 var(--mono); tab-size: 4; }
td pre { white-space: pre-wrap; overflow-wrap: anywhere; margin-top: 8px; border-radius: 6px; }
footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid var(--edge);
  color: var(--muted); font-size: 12px; }
footer details { border: 0; background: none; }
footer summary { padding: 8px 0; font-weight: 400; }
footer pre { white-space: pre-wrap; }
@media (max-width: 700px) {
  .report { padding: 0 16px 24px; }
  .topbar { padding: 16px 0; }
  .brand span { display: none; }
  .report-heading { padding-top: 26px; }
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
  .card { padding: 14px; }
  .card-value { font-size: 20px; }
  .graph-scroll { padding: 12px; }
}
"""
    + f"@media print {{ .report, #theme-light:checked ~ .report {{{_palette(LIGHT)};color-scheme:light}} }}\n"
    + """
@media print {
  .report { padding: 0; background: white; }
  .theme-switch, .theme-choice, nav { display: none; }
  .topbar { padding-top: 0; }
  .graph-scroll { max-height: none; overflow: visible; background: none; padding: 12px; }
  .graph-scroll > svg { width: 100% !important; height: auto; }
  .table-wrap { overflow: visible; }
  .activities { min-width: 0; table-layout: fixed; }
  .activities td { min-width: 0; }
  th, td { padding: 6px; font-size: 10px; }
  details > :not(summary) { display: block !important; }
  details::details-content { content-visibility: visible; }
  details pre { white-space: pre-wrap; overflow-wrap: anywhere; }
  tr, .card { break-inside: avoid; }
  thead { display: table-header-group; }
}
"""
)

DOCUMENT: Final = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogarX — activity reconstruction for {ip}</title>
<style>{style}</style></head>
<body>
<input class="theme-choice" type="radio" name="theme" id="theme-dark" aria-label="Dark theme" checked>
<input class="theme-choice" type="radio" name="theme" id="theme-light" aria-label="Light theme">
<div class="report">
<header class="topbar">
<div class="brand"><svg viewBox="0 0 28 28" aria-hidden="true">
<path d="M6 5V23L23 12" fill="none" stroke="currentColor" stroke-width="2.5"/>
<circle cx="6" cy="5" r="4" fill="currentColor"/>
<circle cx="23" cy="12" r="4" fill="currentColor"/>
<circle cx="6" cy="23" r="4" fill="var(--page)" stroke="currentColor" stroke-width="2.5"/>
</svg>LogarX <span>Investigation report</span></div>
<div class="theme-switch" role="group" aria-label="Report appearance">
<label for="theme-dark">Dark</label><label for="theme-light">Light</label>
</div></header>
<main>
<div class="report-heading"><p class="eyebrow">Activity reconstruction</p>
<h1>Client <span class="client">{ip}</span></h1>
<p class="subtitle">Reconstructed from access logs · Observed responses do not prove an exploit succeeded.</p>
</div>
<nav aria-label="Report sections"><a href="#trace">Reconstruction</a>
<a href="#behaviour">Behaviour map</a><a href="#activities">Activities</a>
<a href="#provenance">Provenance</a></nav>
<div class="cards">{summary}</div>
<section id="trace"><div class="section-heading"><h2>What happened, in order</h2>
<p>Activities grouped by session. Follow the arrows.</p></div>
<div class="panel"><div class="graph-scroll" tabindex="0" role="region" aria-label="Chronological graph">{trace}</div>{legend}</div>
</section>
<section id="behaviour"><div class="section-heading"><h2>How this client behaved</h2>
<p>Repeated activity types combined into one view.</p></div>
<div class="panel"><div class="graph-scroll" tabindex="0" role="region" aria-label="Behaviour graph">{behaviour}</div></div>
</section>
<section id="activities"><div class="section-heading"><h2>Activities</h2><p>Recorded times are UTC.</p></div>
<div class="table-wrap" tabindex="0" role="region" aria-label="Activities table">
<table class="activities"><thead><tr>
<th scope="col">Time</th><th scope="col">Activity</th><th scope="col">Severity</th><th scope="col">OWASP</th>
<th scope="col">Requests</th><th scope="col">Outcome</th><th scope="col">Top targets</th><th scope="col">Evidence</th>
</tr></thead><tbody>{episodes}</tbody></table></div></section>
{bookmarks}
<details id="provenance"><summary><h2>Provenance</h2></summary>
<div class="table-wrap" tabindex="0" role="region" aria-label="Provenance table">
<table><thead><tr><th scope="col">Item</th><th scope="col">Value</th></tr></thead>
<tbody>{provenance}</tbody></table></div></details>
<details><summary>Machine-readable data</summary><pre>{payload}</pre></details>
<footer>Generated by LogarX · Self-contained report · No network connection required.</footer>
</main></div></body></html>
"""
