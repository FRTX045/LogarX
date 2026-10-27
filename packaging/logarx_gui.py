"""Entry script for the frozen Windows build.

A launcher rather than pointing PyInstaller at `logarx/gui/app.py` directly:
used as the entry script that module would be imported as `__main__`, and any
later import of `logarx.gui.app` would load a second, separate copy of it.
"""

from __future__ import annotations

from logarx.gui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
