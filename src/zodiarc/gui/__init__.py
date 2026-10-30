"""The desktop interface.

The only layer that imports Qt. The workflow lives in `zodiarc.case` and
`zodiarc.analysis`, and both interfaces drive those same functions, so a
reconstruction is the same reconstruction whichever one asked for it — a rule
that holds by construction rather than by discipline.

Two results are the window's alone: the canvas as a PNG, and a reconstruction
over a stretch of time. Both are named in `app`'s docstring with the reason.
Every other analysis it can ask for is reachable from the command line.

The decisions about how a finding should *look* are not made here at all.
They are plain data in `zodiarc.style`, with no Qt import, so they can be tested
without a display and reused by the HTML report, and the widgets here only draw
what that module decides.
"""

from __future__ import annotations
