"""The rule packs bundled with the tool.

These are data, not code. An investigator extends detection by adding YAML
alongside them or passing their own directory, without touching the engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

from logarx.detect.rules import load_rules

if TYPE_CHECKING:
    from logarx.detect.rules import Rule

__all__ = ["DEFAULT_RULEPACK_DIR", "default_rules"]

DEFAULT_RULEPACK_DIR: Final = Path(__file__).parent


def default_rules() -> list[Rule]:
    """Load every rule pack shipped with the tool."""
    return load_rules([DEFAULT_RULEPACK_DIR])
