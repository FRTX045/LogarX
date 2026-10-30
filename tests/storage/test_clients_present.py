"""Which of some addresses a case holds, asked once however many there are.

What a bookmark's client is checked against: a bookmark made in one case and
carried to another, or kept across a re-ingest, may name an address that is no
longer there.
"""

from __future__ import annotations

from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from test_event_store import event

from zodiarc.storage.event_store import ParquetEventStore

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def store(tmp_path: Path) -> Iterator[ParquetEventStore]:
    with closing(ParquetEventStore(tmp_path / "case")) as opened:
        opened.write(
            [event("10.0.0.1"), event("2001:db8::1", line_no=2), event("10.0.0.12", line_no=3)]
        )
        opened.finalize()
        yield opened


def test_only_the_addresses_the_case_holds_come_back(store: ParquetEventStore) -> None:
    asked = {"10.0.0.1", "2001:db8::1", "10.0.0.9"}
    assert store.clients_present(asked) == frozenset({"10.0.0.1", "2001:db8::1"})


def test_part_of_an_address_is_not_that_address(store: ParquetEventStore) -> None:
    assert store.clients_present({"10.0.0", "0.0.1"}) == frozenset()


def test_asking_about_nobody_answers_nobody(store: ParquetEventStore) -> None:
    assert store.clients_present(set()) == frozenset()


def test_the_addresses_handed_over_are_not_left_behind(store: ParquetEventStore) -> None:
    store.clients_present({"10.0.0.1"})
    left = (
        store._connect()
        .execute("SELECT count(*) FROM duckdb_views() WHERE view_name LIKE 'chosen_%'")
        .fetchone()
    )
    assert left == (0,)
