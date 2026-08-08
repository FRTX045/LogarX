"""logarc — forensic reconstruction of per-IP web activity from server access logs."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("logarc")
except PackageNotFoundError:  # pragma: no cover - only when running from a source tree
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
