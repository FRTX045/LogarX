"""Converting the CSIC 2010 traces into something logarc can read."""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.core.evidence import EvidenceRef
from logarc.evaluation.csic import CsicError, convert_csic
from logarc.evaluation.truth import read_truth
from logarc.parsers.registry import get_parser

NORMAL = """\
GET http://localhost:8080/tienda1/index.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Host: localhost:8080
Cookie: JSESSIONID=B92A8B48B9008CD29F622A994E0F650D
Connection: close

GET http://localhost:8080/tienda1/publico/anadir.jsp?id=2&precio=85 HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Host: localhost:8080
Cookie: JSESSIONID=B92A8B48B9008CD29F622A994E0F650D
Connection: close

POST http://localhost:8080/tienda1/publico/registro.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Host: localhost:8080
Cookie: JSESSIONID=0000000000000000000000000000AAAA
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Connection: close

nombre=Ana&apellidos=Lopez
"""

ANOMALOUS = """\
GET http://localhost:8080/tienda1/publico/anadir.jsp?id=2%27%3B+DROP+TABLE+usuarios%3B+-- HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Host: localhost:8080
Cookie: JSESSIONID=1111111111111111111111111111BBBB
Connection: close

POST http://localhost:8080/tienda1/publico/entrar.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
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


def test_every_request_becomes_a_parseable_log_line(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    normal, anomalous = dataset
    log = tmp_path / "csic.log"

    result = convert_csic(normal=[normal], anomalous=[anomalous], out=log)

    assert result.requests == 5
    parser = get_parser("apache-combined")
    for number, text in enumerate(log.read_text(encoding="utf-8").splitlines(), start=1):
        event = parser.parse_line(text, EvidenceRef("csic.log", number))
        assert event is not None, text
        assert event.method in {"GET", "POST"}


def test_a_session_cookie_becomes_a_client(dataset: tuple[Path, Path], tmp_path: Path) -> None:
    """The dataset has no addresses, and per-IP reconstruction needs clients.

    A session is the closest thing the traces carry to one person's visit, so
    each distinct JSESSIONID is given an address of its own.
    """
    normal, anomalous = dataset
    log = tmp_path / "csic.log"

    convert_csic(normal=[normal], anomalous=[anomalous], out=log)

    addresses = [line.split(" ", 1)[0] for line in log.read_text(encoding="utf-8").splitlines()]
    assert addresses[0] == addresses[1], "one session, one client"
    assert len(set(addresses)) == 3


def test_the_truth_records_only_attack_or_not(dataset: tuple[Path, Path], tmp_path: Path) -> None:
    """The dataset says a request is an attack, never which kind."""
    normal, anomalous = dataset
    log = tmp_path / "csic.log"
    truth_path = tmp_path / "csic.truth.jsonl"

    convert_csic(normal=[normal], anomalous=[anomalous], out=log, truth_path=truth_path)

    truth = read_truth(truth_path)
    assert truth.granularity == "binary"
    assert truth.line_count == 5
    assert sum(record.category.is_hostile for record in truth.records) == 2


def test_post_bodies_are_left_out_because_an_access_log_has_none(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    """Putting them in would hand the tool evidence it can never really have.

    Roughly half of CSIC's attacks live in a POST body. A web server access log
    records the request line and nothing after it, so those attacks are simply
    not visible here — and the count is reported rather than quietly fixed.
    """
    normal, anomalous = dataset
    log = tmp_path / "csic.log"

    result = convert_csic(normal=[normal], anomalous=[anomalous], out=log)

    assert "login=admin" not in log.read_text(encoding="utf-8")
    assert result.attacks_hidden_in_bodies == 1


def test_bodies_can_be_included_for_the_comparison(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    normal, anomalous = dataset
    log = tmp_path / "csic.log"

    convert_csic(normal=[normal], anomalous=[anomalous], out=log, include_bodies=True)

    assert "login=admin" in log.read_text(encoding="utf-8")


def test_requests_are_given_increasing_timestamps(
    dataset: tuple[Path, Path], tmp_path: Path
) -> None:
    normal, anomalous = dataset
    log = tmp_path / "csic.log"

    convert_csic(normal=[normal], anomalous=[anomalous], out=log)

    parser = get_parser("apache-combined")
    stamps = [
        parser.parse_line(text, EvidenceRef("csic.log", n)).timestamp  # type: ignore[union-attr]
        for n, text in enumerate(log.read_text(encoding="utf-8").splitlines(), start=1)
    ]
    assert stamps == sorted(stamps)


def test_a_file_that_is_not_csic_is_an_error(tmp_path: Path) -> None:
    junk = tmp_path / "junk.txt"
    junk.write_text("this is not a trace file\n", encoding="utf-8")

    with pytest.raises(CsicError, match="no HTTP requests"):
        convert_csic(normal=[junk], anomalous=[], out=tmp_path / "out.log")
