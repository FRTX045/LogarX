from contextlib import closing
from datetime import timedelta

from test_event_store import START, event

from logarc.core.window import TimeWindow
from logarc.storage.event_store import ParquetEventStore


def test_summary_search_includes_quiet_clients_beyond_500_and_retains_positions(tmp_path):
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write([event(f"client-{i:04}", line_no=i + 1) for i in range(605)])
        store.finalize()
        page = store.ip_summary_page(query="client-060", limit=2)
        assert page.total == 5
        assert [row.position for row in page.rows] == [601, 602]
        assert [row.client_ip for row in page.rows] == ["client-0600", "client-0601"]
        next_page = store.ip_summary_page(query="client-060", limit=2, offset=4)
        assert next_page.total == 5
        assert next_page.rows[0].position == 605
        empty = store.ip_summary_page(query="client-060", offset=10)
        assert empty.total == 5 and not empty.rows
        assert not store.ip_summary_page(query="%' OR true --").rows


def test_summary_page_aggregates_inclusive_time_bounds_and_empty_cases(tmp_path):
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write([event("a"), event("b", offset_seconds=1), event("a", offset_seconds=2)])
        store.finalize()
        page = store.ip_summary_page(window=TimeWindow(START, START + timedelta(seconds=1)))
        assert page.total == 2
        assert [row.request_count for row in page.rows] == [1, 1]
        assert [row.position for row in page.rows] == [1, 2]
    with closing(ParquetEventStore(tmp_path / "empty")) as store:
        store.finalize()
        assert store.ip_summary_page().total == 0
