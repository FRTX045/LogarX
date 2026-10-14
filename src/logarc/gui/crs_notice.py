"""What the window says when a case was checked with an older CRS.

Free of Qt, for the same reason `gui.format_notice` beside it is: the judgement
is what can mislead, and only the drawing needs a display.

A case keeps the CRS results it was enriched with, and the fingerprint of the
configuration that made them. When that configuration has moved since (a newer
ruleset, other settings, or a sidecar that reads requests differently), the
results may miss what CRS finds today. That happened on 2026-10-14: the Windows
sidecar had been missing every file-path attack, and a case checked before the
fix keeps showing what it missed until CRS runs on it again.

The fingerprint already names everything that changes what CRS reports, so a
difference in it is the whole test, with one exception. A paranoia level chosen
on the command line is a decision, not an old version, and running CRS again
from the window would quietly undo it at the default level.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from logarc.gui.quarantine_notice import Notice

if TYPE_CHECKING:
    from collections.abc import Mapping

    from logarc.detect.crs import SidecarConfig

__all__ = ["stale_crs_notice"]


def stale_crs_notice(
    made_with: Mapping[str, Any] | None, now: SidecarConfig | None
) -> Notice | None:
    """What to say about a case whose CRS results `made_with` recorded, or nothing.

    `made_with` is the case's recorded configuration, or None when the case
    holds no CRS results. `now` is the configuration running CRS again would
    use, or None when CRS cannot run on this computer, where an offer to run it
    would only fail.
    """
    if made_with is None or now is None:
        return None
    recorded = made_with.get("crs_fingerprint")
    if not recorded:
        return None
    if made_with.get("crs_paranoia_level", now.paranoia) != now.paranoia:
        return None
    if recorded == now.fingerprint():
        return None

    return Notice(
        headline="This case was checked with an older CRS",
        detail=(
            "Its CRS results may miss attacks the CRS here would find. Run CRS "
            "again to replace them; nothing else in the case changes."
        ),
        dead_files=(),
    )
