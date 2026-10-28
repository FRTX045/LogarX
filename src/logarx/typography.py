"""Font preferences shared by the desktop and offline reports, without Qt.

Use installed fonts so reports remain self-contained: no web-font downloads or
system-specific file paths. The first available family wins on each machine.
"""

from typing import Final

#: Windows 11's text face, then Windows, Inter and the platform sans-serif.
UI_FAMILIES: Final = ("Segoe UI Variable Text", "Segoe UI", "Inter", "sans-serif")
#: Fixed-width evidence keeps addresses and raw log fields aligned.
MONO_FAMILIES: Final = ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "monospace")
