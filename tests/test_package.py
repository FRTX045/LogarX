"""Smoke test: the package imports and reports a version.

Deliberately minimal — it exists so CI has something to run from the first commit,
and it catches packaging mistakes (bad `src` layout, missing wheel config) that
would otherwise only surface much later.
"""

import logarc


def test_package_exposes_version() -> None:
    assert isinstance(logarc.__version__, str)
    assert logarc.__version__
