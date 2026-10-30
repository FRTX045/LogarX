"""Smoke test: the package imports and reports a version.

Deliberately minimal — it exists so CI has something to run from the first commit,
and it catches packaging mistakes (bad `src` layout, missing wheel config) that
would otherwise only surface much later.
"""

import zodiarc


def test_package_exposes_version() -> None:
    assert isinstance(zodiarc.__version__, str)
    assert zodiarc.__version__
