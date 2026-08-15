"""Reading a case whose ingest never finished.

Not a hypothetical state: cancelling an ingest leaves the case exactly here on
purpose, so the part that was read is not thrown away, and the window says so —
"holds what had been read by then and was not finalised, so it cannot be
analysed". Someone told that will reasonably try a command against it, and the
answer has to be that same sentence rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.case import Case
from logarc.cli.main import app

runner = CliRunner()


@pytest.fixture
def unfinalised(tmp_path: Path) -> Path:
    """A case created and then abandoned, as a cancelled ingest leaves one."""
    root = tmp_path / "cancelled"
    with Case.create(root):
        pass
    return root


@pytest.mark.parametrize(
    ("command", "extra"),
    [
        ("list-ips", []),
        ("analyze", ["--ip", "203.0.113.5"]),
        ("evidence", ["--ip", "203.0.113.5"]),
        ("enrich", []),
    ],
)
def test_a_command_explains_an_unfinished_case(
    unfinalised: Path, command: str, extra: list[str]
) -> None:
    result = runner.invoke(app, [command, "--case", str(unfinalised), *extra])

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        f"{command} crashed instead of explaining: {result.exception!r}"
    )
    assert "finalis" in " ".join(result.output.split()), f"{command} said nothing useful"


def test_exporting_an_unfinished_case_explains_itself(unfinalised: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "export", "--case", str(unfinalised), "--ip", "203.0.113.5",
            "--format", "json", "--out", str(tmp_path / "out.json"),
        ],
    )  # fmt: skip

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "finalis" in " ".join(result.output.split())
