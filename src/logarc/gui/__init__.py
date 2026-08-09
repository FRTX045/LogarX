"""The desktop interface.

The only layer that imports Qt. Everything it can do is also reachable from the
CLI, because the workflow lives in `logarc.case` and `logarc.analysis` and both
interfaces drive the same functions — the rule holds by construction rather than
by discipline.

`style` is the exception that proves it: the decisions about how a finding
should *look* are made there as plain data, with no Qt import, so they can be
tested without a display and reused by the HTML report.
"""

from __future__ import annotations
