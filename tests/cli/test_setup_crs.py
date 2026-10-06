"""`logarc setup-crs`: the command line's half of `logarc.detect.crs.setup`."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from logarc.cli import main as cli_main
from logarc.cli.main import app
from logarc.detect.crs.setup import SetupError

runner = CliRunner()


def test_it_says_what_it_did(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main, "setup_crs", lambda: ["Ruleset: already at d694d465", "Sidecar: built x"]
    )

    result = runner.invoke(app, ["setup-crs"])

    assert result.exit_code == 0, result.output
    assert "Ruleset: already at d694d465" in result.output
    assert "Sidecar: built x" in result.output


def test_what_it_could_not_do_is_a_failure_with_the_remedy(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_go() -> list[str]:
        raise SetupError("Go is not installed. Install Go 1.25 or newer from go.dev.")

    monkeypatch.setattr(cli_main, "setup_crs", missing_go)

    result = runner.invoke(app, ["setup-crs"])

    assert result.exit_code == 1
    assert "go.dev" in result.output
