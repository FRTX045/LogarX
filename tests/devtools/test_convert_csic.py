"""The `convert-csic` command.

The conversion itself is covered in tests/evaluation/test_csic.py. What is
covered here is the part only the command does: refusing an empty invocation,
turning a conversion failure into a message rather than a traceback, and
printing the two caveats that stop a number from being quoted as more than it
is. The dataset is not shipped, so nothing exercised this wrapper at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarx.devtools.main import app

runner = CliRunner()

#: Two ordinary requests and two attacks, one of which hides its payload in a
#: POST body. That ratio is the point: it makes the ceiling exactly 50%.
NORMAL = """\
GET http://localhost:8080/tienda1/index.jsp HTTP/1.1
User-Agent: Mozilla/5.0
Host: localhost:8080
Cookie: JSESSIONID=B92A8B48B9008CD29F622A994E0F650D
Connection: close

GET http://localhost:8080/tienda1/publico/anadir.jsp?id=2 HTTP/1.1
User-Agent: Mozilla/5.0
Host: localhost:8080
Cookie: JSESSIONID=B92A8B48B9008CD29F622A994E0F650D
Connection: close
"""

ANOMALOUS = """\
GET http://localhost:8080/tienda1/publico/anadir.jsp?id=2%27%3B+DROP+TABLE+x%3B+-- HTTP/1.1
User-Agent: Mozilla/5.0
Host: localhost:8080
Cookie: JSESSIONID=1111111111111111111111111111BBBB
Connection: close

POST http://localhost:8080/tienda1/publico/entrar.jsp HTTP/1.1
User-Agent: Mozilla/5.0
Host: localhost:8080
Cookie: JSESSIONID=1111111111111111111111111111BBBB
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Connection: close

login=admin%27+OR+%271%27%3D%271&pwd=x
"""


@pytest.fixture
def dataset(tmp_path: Path) -> tuple[Path, Path]:
    normal = tmp_path / "normalTrafficTest.txt"
    anomalous = tmp_path / "anomalousTrafficTest.txt"
    normal.write_text(NORMAL, encoding="utf-8")
    anomalous.write_text(ANOMALOUS, encoding="utf-8")
    return normal, anomalous


def test_converting_writes_a_log_and_says_what_is_in_it(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    normal, anomalous = dataset
    out = tmp_path / "csic.log"

    result = runner.invoke(
        app,
        ["convert-csic", "--normal", str(normal), "--anomalous", str(anomalous), "--out", str(out)],
    )

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "4 requests" in result.output


def test_the_command_says_how_much_recall_it_can_possibly_reach(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    """The caveat this dataset cannot be quoted without.

    Half of CSIC's attacks carry their payload in a POST body, and an access log
    records the request line and nothing after it. Those are unreachable by
    construction rather than missed, so a recall figure from this corpus is a
    fraction of a ceiling — and a number that looks like a result and is not one
    is the worst thing this tool can print.
    """
    normal, anomalous = dataset
    out = tmp_path / "csic.log"

    result = runner.invoke(
        app,
        ["convert-csic", "--normal", str(normal), "--anomalous", str(anomalous), "--out", str(out)],
    )

    assert result.exit_code == 0, result.output
    printed = " ".join(result.output.split())
    assert "50%" in printed, "the ceiling has to be stated as a number"
    assert "POST" in printed
    # The second caveat: no responses means outcome cannot be scored at all.
    assert "outcome cannot be evaluated" in printed


def test_including_bodies_withdraws_the_ceiling_warning(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    """With bodies folded in, nothing is hidden and the warning would be false."""
    normal, anomalous = dataset
    out = tmp_path / "csic.log"

    result = runner.invoke(
        app,
        [
            "convert-csic", "--normal", str(normal), "--anomalous", str(anomalous),
            "--out", str(out), "--include-bodies",
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert "cannot exceed" not in " ".join(result.output.split())


def test_ground_truth_is_reported_when_it_is_asked_for(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    normal, anomalous = dataset
    out = tmp_path / "csic.log"
    truth = tmp_path / "csic.truth.jsonl"

    result = runner.invoke(
        app,
        [
            "convert-csic", "--normal", str(normal), "--anomalous", str(anomalous),
            "--out", str(out), "--truth", str(truth),
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert truth.exists()
    # The phrase, not the path: Rich wraps a long path across lines, so
    # asserting on the whole string measures the console width of whoever ran
    # the suite rather than anything the command did.
    assert "Ground truth written" in " ".join(result.output.split())


def test_converting_nothing_is_refused(tmp_path: Path) -> None:
    result = runner.invoke(app, ["convert-csic", "--out", str(tmp_path / "csic.log")])

    assert result.exit_code == 1
    assert "--normal" in result.output


def test_a_file_that_is_not_csic_is_reported_not_crashed(tmp_path: Path) -> None:
    junk = tmp_path / "junk.txt"
    junk.write_text("this is not a trace file\n", encoding="utf-8")

    result = runner.invoke(
        app, ["convert-csic", "--normal", str(junk), "--out", str(tmp_path / "csic.log")]
    )

    assert result.exit_code == 1
    assert "Traceback" not in result.output
