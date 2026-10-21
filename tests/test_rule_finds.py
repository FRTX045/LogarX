"""What a pack finds in the open case: lines labelled and the clients behind them.

Counted from every label a rule put on a line, not only the one that won, so a
rule that fires and loses still shows. On the bundled shopfront log the example
pack finds 29 lines from 7 clients, and 1 line from 1 client.

The preview (2026-10-21) said 32 lines. It labelled each client whole, while a
reconstruction labels one session at a time, and two runs of polling straddle a
session boundary (100.70.92.188 lines 517 and 524, 100.65.225.167 line 722). The
panel shows what the graph will credit, so 29 is the answer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.detect.rules import load_pack_text
from logarc.detect.ruleset import build_rules
from logarc.rule_finds import Find, FindsCancelled, count_finds

SHOPFRONT_LOG = Path(__file__).parent / "data" / "apache-shopfront" / "excerpt.log"

SHOPFRONT = """\
version: 1
rules:
  - id: shop_stock_polling
    name: Stock levels polled by a script
    category: crawling
    severity: low
    confidence: 0.7
    member:
      all:
        - {field: path, regex: "^/api/stock$"}
    window:
      span_seconds: 300
      min_requests: 3
      conditions:
        - {metric: request_count, op: ">=", value: 3}

  - id: shop_cart_emptied_by_api
    name: Cart emptied through the API
    category: api_call
    severity: info
    match:
      all:
        - {field: method, equals: DELETE}
        - {field: path, regex: "^/api/cart$"}
"""


@pytest.fixture(scope="module")
def shopfront(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("finds") / "case"
    with Case.create(root) as case:
        case.ingest([SHOPFRONT_LOG])
    return root


def test_the_example_pack_s_counts_on_the_shopfront_log(shopfront: Path) -> None:
    rules = load_pack_text("shopfront.yaml", SHOPFRONT)

    assert count_finds(shopfront, rules) == {
        "shop_stock_polling": Find(lines=29, clients=7),
        "shop_cart_emptied_by_api": Find(lines=1, clients=1),
    }


def test_counting_a_few_rules_alone_agrees_with_every_rule_together(shopfront: Path) -> None:
    """The count builds an engine of only the rules on show, because no rule's
    label depends on another's. If that stopped being true, the panel would
    show numbers the reconstruction does not."""
    every = build_rules().rules
    shown = [rule for rule in every if rule.source_pack == "recon.yaml"]

    alone = count_finds(shopfront, shown)
    together = count_finds(shopfront, every)

    assert alone == {rule.id: together[rule.id] for rule in shown}


def test_a_rule_that_finds_nothing_is_still_counted(shopfront: Path) -> None:
    rules = load_pack_text("x.yaml", SHOPFRONT.replace("^/api/cart$", "^/never$"))

    assert count_finds(shopfront, rules)["shop_cart_emptied_by_api"] == Find(0, 0)


def test_the_count_says_how_far_it_has_got(shopfront: Path) -> None:
    seen = []

    count_finds(shopfront, load_pack_text("x.yaml", SHOPFRONT), report=seen.append, every=0)

    assert seen
    assert seen[-1].done == seen[-1].total
    assert [p.done for p in seen] == sorted(p.done for p in seen)


def test_the_count_stops_when_asked(shopfront: Path) -> None:
    with pytest.raises(FindsCancelled):
        count_finds(shopfront, load_pack_text("x.yaml", SHOPFRONT), cancelled=lambda: True)


def test_the_count_is_what_a_reconstruction_credits(shopfront: Path) -> None:
    """Cross-checked against reconstructing every client, which is what the
    graph shows. Labelling each client whole instead counts three more lines."""
    rules = load_pack_text("x.yaml", SHOPFRONT)
    credited = 0
    with Case.open(shopfront) as case:
        engine = case.engine_for(rules)
        for events in case.store.iter_clients():
            result = analyse_ip(case.store, events[0].client_ip, engine=engine)
            credited += sum(
                any(label.rule_id == "shop_stock_polling" for label in item.labelled.all_labels)
                for item in result.assignments
            )

    assert count_finds(shopfront, rules)["shop_stock_polling"].lines == credited


def _cart_line() -> int:
    (number,) = [
        number
        for number, text in enumerate(SHOPFRONT_LOG.read_text(encoding="utf-8").splitlines(), 1)
        if "DELETE /api/cart" in text
    ]
    return number


def test_examples_are_the_first_lines_a_rule_labels(shopfront: Path) -> None:
    rules = load_pack_text("shopfront.yaml", SHOPFRONT)

    (example,) = count_finds(shopfront, rules, examples=3)["shop_cart_emptied_by_api"].examples

    assert example.ref.line_no == _cart_line()
    assert example.request.startswith("DELETE /api/cart")
    assert example.status is not None


def test_no_examples_unless_asked(shopfront: Path) -> None:
    rules = load_pack_text("shopfront.yaml", SHOPFRONT)

    finds = count_finds(shopfront, rules)

    assert all(find.examples == () for find in finds.values())
    assert finds["shop_stock_polling"] == Find(lines=29, clients=7)


def test_examples_stop_at_the_limit(shopfront: Path) -> None:
    rules = load_pack_text("shopfront.yaml", SHOPFRONT)

    finds = count_finds(shopfront, rules, examples=2)

    assert len(finds["shop_stock_polling"].examples) == 2
    assert finds["shop_stock_polling"].lines == 29
