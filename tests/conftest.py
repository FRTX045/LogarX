"""Puts `tests/` on the import path, which is the whole of its job.

pytest inserts a conftest's own directory before importing it, and that is
what lets `tests/gui` and `tests/report` reach `colours.py` beside it. The
arithmetic itself moved to that module: reached as `conftest` it was one
sibling directory away from being shadowed, and then was.
"""

from __future__ import annotations
