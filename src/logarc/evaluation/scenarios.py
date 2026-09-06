"""What the synthetic clients do.

Each role is a script: a sequence of requests one client makes, with the
activity each request belongs to declared alongside it. The declaration is the
ground truth, so it has to be written from the *behaviour*, never from what the
rules happen to catch. Labelling a burst "enumeration" because the enumeration
rule fires on it would make the evaluation a tautology.

Two categories sit close enough together to need a stated boundary, used
consistently here:

* **reconnaissance** — probing for particular known-interesting artefacts:
  configuration files, backups, debug endpoints, a component with a known CVE.
  Few requests, chosen deliberately.
* **enumeration** — sweeping a wordlist to find out what exists at all. Many
  requests, no prior knowledge of any of them.

The truth is written at the grain of what the client is doing, not of what each
request is. A shopper reading a page, the assets that page pulls in and the
cart call it fires are one activity: the shopper did one thing, and it took
three kinds of request. So every ordinary-use step of one script shares one
activity, and only a pause ends it. This is a statement about the script, and
it is the grain `episode.builder` draws at, which is what lets the boundary
score measure the segmenter rather than a disagreement over what a page load is.
Hostile steps keep an activity of their own however they are made: probing,
sweeping and trying restricted areas are three things, and an attack between
two page loads is never part of either.

Clients are addressed out of the shared address space (100.64.0.0/10), one /16
per role. It routes nowhere, so no synthetic finding can ever be mistaken for
one about a real host, and it is a range that genuinely appears in access logs
from clients behind carrier NAT.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

from logarc.core.activity import ActivityCategory as Category

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from random import Random

__all__ = ["SCENARIOS", "Actor", "Role", "Scenario", "Step"]


@dataclass(frozen=True, slots=True)
class Step:
    """One request a client makes."""

    activity: str
    """What the client is doing. A change of value starts a new activity."""

    category: Category
    path: str
    method: str = "GET"
    query: str | None = None
    status: int = 200
    size: int = 0
    referer: str | None = None
    gap: float = 2.0
    """Seconds since this client's previous request."""

    resumed: bool = False
    """The client had gone away and has come back: a fresh act.

    Stated by the scenario rather than inferred from `gap`, because the whole
    point of sweeping the gap thresholds is to ask which of them agrees with
    intent. Deriving intent from a gap size would make that circular — the
    truth would agree with whatever setting was being tested.
    """


@dataclass(frozen=True, slots=True)
class Actor:
    """One client and everything it will do."""

    user_agent: str
    steps: Iterator[Step]


@dataclass(frozen=True, slots=True)
class Role:
    """A kind of client, and the /16 its addresses are drawn from."""

    name: str
    octet: int
    build: Callable[[Random], Actor]


@dataclass(frozen=True, slots=True)
class Scenario:
    """A mix of clients, present in the stated proportions for the whole run.

    The mix is spelled out rather than sampled from weights so that a scenario
    named after an attack always contains one, however few lines are asked for.
    """

    name: str
    description: str
    mix: tuple[Role, ...]


# -- shared vocabulary -------------------------------------------------------

_BROWSER_AGENTS: Final = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, "
    "like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
)

_CRAWLER_AGENTS: Final = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
)

_SCANNER_AGENTS: Final = (
    "Mozilla/5.0 (compatible; Nikto/2.5.0)",
    "sqlmap/1.8.4#stable (https://sqlmap.org)",
    "gobuster/3.6",
)

_SITE: Final = "https://shop.example.com"

_PAGES: Final = (
    "/",
    "/products",
    "/products/running-shoes",
    "/products/trail-shoes",
    "/products/waterproof-jacket",
    "/collections/spring",
    "/about",
    "/contact",
    "/blog",
    "/blog/choosing-a-trail-shoe",
    "/cart",
)

_ASSETS: Final = (
    "/assets/app.css",
    "/assets/app.js",
    "/assets/logo.png",
    "/assets/hero.jpg",
    "/assets/fonts/inter.woff2",
    "/favicon.ico",
)

_BROKEN_LINKS: Final = (
    "/help/shipping-old",
    "/sale/summer-2023",
    "/account/orders/legacy",
    "/blog/retired-post",
    "/support/returns-old",
)

#: A generic content-discovery wordlist, of the kind any scanner ships with.
_WORDLIST: Final = (
    "/backup", "/backups", "/old", "/new", "/test", "/tmp", "/temp", "/dev",
    "/staging", "/db", "/database", "/sql", "/dump", "/data", "/private",
    "/secret", "/hidden", "/internal", "/uploads", "/upload", "/files",
    "/download", "/downloads", "/media", "/images/private", "/cgi-bin/test.cgi",
    "/cgi-bin/status", "/scripts/setup.php", "/install", "/installer",
    "/setup", "/setup.php", "/register.php", "/user/register", "/api/v1/users",
    "/api/internal", "/graphql", "/console", "/portal", "/dashboard",
    "/webmail", "/mail", "/owa", "/vpn", "/remote", "/jenkins", "/gitlab",
    "/nagios", "/munin", "/awstats", "/webalizer", "/stats", "/counter",
    "/logs", "/log", "/error_log", "/access_log", "/debug", "/trace",
)  # fmt: skip

#: Artefacts a scanner asks for by name because it knows what they are.
_KNOWN_ARTEFACTS: Final = (
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/config.php.save",
    "/database.sql",
    "/phpinfo.php",
    "/server-status",
    "/.svn/entries",
    "/composer.json",
    "/package-lock.json",
)

_ADMIN_AREAS: Final = (
    "/admin",
    "/admin/users",
    "/admin/settings",
    "/administrator/index.php",
    "/wp-admin/",
    "/wp-admin/users.php",
    "/phpmyadmin/",
    "/manager/html",
    "/console",
    "/admin/backup",
    "/admin/logs",
    "/admin/config",
)

_SQLI_PAYLOADS: Final = (
    "5' OR '1'='1",
    "5 UNION SELECT null,null,null--",
    "5 UNION ALL SELECT username,password FROM users--",
    "5' AND SLEEP(5)--",
    "5' UNION SELECT table_name FROM information_schema.tables--",
    "5'; DROP TABLE sessions--",
    "5' OR 1=1--",
    "5' AND 1=CONVERT(int,@@version)--",
)

_TRAVERSAL_PAYLOADS: Final = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "../../../../windows/win.ini",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "../../../proc/self/environ",
)


def _encode(value: str) -> str:
    """Percent-encode a parameter value, as any client would."""
    return quote(value, safe="")


# -- roles -------------------------------------------------------------------


def _browse(rng: Random) -> Actor:
    """Someone shopping: pages, the assets each page pulls in, a little API."""

    def steps() -> Iterator[Step]:
        referer: str | None = None
        for _ in range(rng.randint(3, 9)):
            page = rng.choice(_PAGES)
            yield Step(
                "reading the site",
                Category.BROWSING,
                path=page,
                status=200,
                size=rng.randint(2_000, 40_000),
                referer=referer,
                gap=rng.uniform(5.0, 45.0),
            )
            referer = f"{_SITE}{page}"

            if rng.random() < 0.15:
                # People put the tab down and come back to it. The request
                # either side is a page view, so nothing but the length of the
                # gap separates the two visits — which is the only arrangement
                # that asks the episode-gap threshold a question. Put the pause
                # next to an asset fetch instead and the change of category
                # decides the boundary before the gap is ever consulted.
                #
                # Kept short of an hour, and uncommon. Clients are merged on
                # time, so a role that spends hours idle contributes far fewer
                # lines than one that does not, and generous pauses here turn a
                # mixed corpus into an almost entirely hostile one.
                page = rng.choice(_PAGES)
                yield Step(
                    "reading the site",
                    Category.BROWSING,
                    path=page,
                    status=200,
                    size=rng.randint(2_000, 40_000),
                    gap=rng.uniform(120.0, 1_800.0),
                    resumed=True,
                )
                referer = f"{_SITE}{page}"
            for asset in rng.sample(_ASSETS, rng.randint(1, 4)):
                yield Step(
                    "reading the site",
                    Category.STATIC_ASSET,
                    path=asset,
                    status=200,
                    size=rng.randint(500, 250_000),
                    referer=referer,
                    gap=rng.uniform(0.05, 0.8),
                )
            if rng.random() < 0.25:
                yield Step(
                    "reading the site",
                    Category.API_CALL,
                    path="/api/v1/cart",
                    method="POST",
                    status=200,
                    size=rng.randint(80, 400),
                    referer=referer,
                    gap=rng.uniform(1.0, 6.0),
                )

        if rng.random() < 0.35:
            yield Step(
                "signing in",
                Category.AUTHENTICATION,
                path="/login",
                method="POST",
                status=302,
                referer=referer,
                gap=rng.uniform(3.0, 20.0),
            )

    return Actor(user_agent=rng.choice(_BROWSER_AGENTS), steps=steps())


def _crawl(rng: Random) -> Actor:
    """A search engine, working politely through the site."""

    def steps() -> Iterator[Step]:
        for path in ("/robots.txt", "/sitemap.xml"):
            yield Step(
                "indexing the site",
                Category.CRAWLING,
                path=path,
                status=200,
                size=rng.randint(200, 4_000),
                gap=rng.uniform(1.0, 5.0),
            )
        for page in rng.sample(_PAGES, min(len(_PAGES), rng.randint(4, 9))):
            yield Step(
                "indexing the site",
                Category.CRAWLING,
                path=page,
                status=200,
                size=rng.randint(2_000, 30_000),
                gap=rng.uniform(8.0, 30.0),
            )

    return Actor(user_agent=rng.choice(_CRAWLER_AGENTS), steps=steps())


def _follow_broken_links(rng: Random) -> Actor:
    """A browser following several dead links from one stale page."""

    def steps() -> Iterator[Step]:
        page = rng.choice(_PAGES)
        yield Step(
            "following links from a stale page",
            Category.BROWSING,
            path=page,
            status=200,
            size=rng.randint(2_000, 40_000),
            gap=rng.uniform(5.0, 45.0),
        )
        referer = f"{_SITE}{page}"
        for path in _BROKEN_LINKS:
            yield Step(
                "following links from a stale page",
                Category.BROWSING,
                path=path,
                status=404,
                referer=referer,
                gap=rng.uniform(10.0, 45.0),
            )

    return Actor(user_agent=rng.choice(_BROWSER_AGENTS), steps=steps())


def _scan(rng: Random) -> Actor:
    """Content discovery from a spoofed browser, which is the normal case.

    A scanner that announces itself in the User-Agent is the easy half of the
    problem. This one does not, so it can only be caught by what it does.
    """

    def steps() -> Iterator[Step]:
        referer = f"{_SITE}/"
        yield Step(
            "arriving",
            Category.BROWSING,
            path="/",
            status=200,
            size=rng.randint(4_000, 20_000),
            gap=1.0,
        )
        for path in rng.sample(_KNOWN_ARTEFACTS, rng.randint(5, 9)):
            yield Step(
                "probing for known artefacts",
                Category.RECONNAISSANCE,
                path=path,
                status=rng.choice((404, 404, 403)),
                referer=referer,
                gap=rng.uniform(0.5, 2.5),
            )
        for path in rng.sample(_WORDLIST, min(len(_WORDLIST), rng.randint(32, 48))):
            yield Step(
                "sweeping a wordlist",
                Category.ENUMERATION,
                path=path,
                status=404,
                referer=referer,
                gap=rng.uniform(0.3, 1.4),
            )
        for path in rng.sample(_ADMIN_AREAS, rng.randint(10, 12)):
            yield Step(
                "trying restricted areas",
                Category.ACCESS_CONTROL,
                path=path,
                status=rng.choice((403, 403, 401)),
                referer=referer,
                gap=rng.uniform(0.5, 3.0),
            )

    return Actor(user_agent=rng.choice(_BROWSER_AGENTS), steps=steps())


def _noisy_scan(rng: Random) -> Actor:
    """A scanner that does not hide, so the User-Agent alone gives it away."""

    def steps() -> Iterator[Step]:
        for path in rng.sample(_KNOWN_ARTEFACTS, rng.randint(6, 10)):
            yield Step(
                "scanning with a named tool",
                Category.RECONNAISSANCE,
                path=path,
                status=rng.choice((404, 403, 200)),
                size=rng.randint(0, 900),
                gap=rng.uniform(0.2, 1.2),
            )

    return Actor(user_agent=rng.choice(_SCANNER_AGENTS), steps=steps())


def _inject(rng: Random) -> Actor:
    """The campaign the tool exists to show: look, probe, inject, then read.

    One payload gets through and returns a large body. That single line is what
    separates "someone tried" from "someone succeeded", and the outcome the
    reconstruction derives has to reflect it.
    """

    def steps() -> Iterator[Step]:
        referer: str | None = None
        for page in ("/", "/products", "/products/running-shoes"):
            yield Step(
                "looking around",
                Category.BROWSING,
                path=page,
                status=200,
                size=rng.randint(3_000, 25_000),
                referer=referer,
                gap=rng.uniform(4.0, 20.0),
            )
            referer = f"{_SITE}{page}"

        for path in rng.sample(_KNOWN_ARTEFACTS, rng.randint(3, 5)):
            yield Step(
                "checking for exposed files",
                Category.RECONNAISSANCE,
                path=path,
                status=404,
                gap=rng.uniform(1.0, 4.0),
            )

        payloads = list(_SQLI_PAYLOADS)
        rng.shuffle(payloads)
        for index, payload in enumerate(payloads):
            # Probing a database with malformed SQL provokes 500s; a few of
            # them are what the traffic really looks like.
            status = 500 if index % 3 == 1 else 403
            yield Step(
                "probing for SQL injection",
                Category.INJECTION,
                path="/products/detail.php",
                query=f"id={_encode(payload)}",
                status=status,
                size=rng.randint(0, 800),
                referer=referer,
                gap=rng.uniform(1.5, 8.0),
            )

        yield Step(
            "probing for SQL injection",
            Category.INJECTION,
            path="/products/detail.php",
            query=f"id={_encode('5 UNION ALL SELECT email,password_hash FROM users--')}",
            status=200,
            size=rng.randint(900_000, 1_800_000),
            referer=referer,
            gap=rng.uniform(2.0, 6.0),
        )

        # Back hours later for more of the same. Injection on both sides of the
        # pause, so only its length distinguishes two visits from one long one:
        # the question the episode gap answers, and — being longer than the
        # idle timeout — the one the session boundary answers too.
        yield Step(
            "returning to the data",
            Category.INJECTION,
            path="/products/detail.php",
            query=f"id={_encode('5 UNION ALL SELECT card_number FROM orders--')}",
            status=200,
            size=rng.randint(400_000, 900_000),
            # Long enough to end a session, short enough that one attacker does
            # not occupy the whole corpus: a client that idles for six hours
            # emits nothing for six hours, and its replacement cannot start
            # until it finishes.
            gap=rng.uniform(2_400.0, 5_400.0),
            resumed=True,
        )

        for page in ("/", "/cart"):
            yield Step(
                "leaving quietly",
                Category.BROWSING,
                path=page,
                status=200,
                size=rng.randint(3_000, 20_000),
                gap=rng.uniform(10.0, 60.0),
            )

    return Actor(user_agent=rng.choice(_BROWSER_AGENTS), steps=steps())


def _brute_force(rng: Random) -> Actor:
    """Guessing a password, then getting in."""

    def steps() -> Iterator[Step]:
        yield Step(
            "opening the login page",
            Category.AUTHENTICATION,
            path="/login",
            status=200,
            size=rng.randint(1_500, 6_000),
            gap=2.0,
        )
        for _ in range(rng.randint(24, 40)):
            yield Step(
                "guessing credentials",
                Category.CREDENTIAL_ATTACK,
                path="/login",
                method="POST",
                status=401,
                size=rng.randint(200, 900),
                gap=rng.uniform(1.5, 6.0),
            )
        yield Step(
            "guessing credentials",
            Category.CREDENTIAL_ATTACK,
            path="/login",
            method="POST",
            status=302,
            gap=rng.uniform(1.5, 6.0),
        )
        yield Step(
            "using the account",
            Category.BROWSING,
            path="/account",
            status=200,
            size=rng.randint(2_000, 9_000),
            gap=rng.uniform(2.0, 8.0),
        )

    return Actor(user_agent=rng.choice(_BROWSER_AGENTS), steps=steps())


def _traverse(rng: Random) -> Actor:
    """Walking out of the document root, one encoding at a time."""

    def steps() -> Iterator[Step]:
        yield Step(
            "finding a file parameter",
            Category.BROWSING,
            path="/download",
            query="file=brochure.pdf",
            status=200,
            size=rng.randint(50_000, 400_000),
            gap=3.0,
        )
        payloads = list(_TRAVERSAL_PAYLOADS)
        rng.shuffle(payloads)
        for payload in payloads:
            yield Step(
                "escaping the document root",
                Category.PATH_TRAVERSAL,
                path="/download",
                query=f"file={_encode(payload)}",
                status=rng.choice((403, 404, 400)),
                size=rng.randint(0, 500),
                gap=rng.uniform(1.0, 6.0),
            )
        yield Step(
            "escaping the document root",
            Category.PATH_TRAVERSAL,
            path="/download",
            query=f"file={_encode('../../../../etc/passwd')}",
            status=200,
            size=rng.randint(1_200, 3_000),
            gap=rng.uniform(1.0, 4.0),
        )

    return Actor(user_agent=rng.choice(_BROWSER_AGENTS), steps=steps())


BROWSER = Role("browser", 64, _browse)
CRAWLER = Role("crawler", 65, _crawl)
SCANNER = Role("scanner", 66, _scan)
INJECTOR = Role("injector", 67, _inject)
GUESSER = Role("guesser", 68, _brute_force)
TRAVERSER = Role("traverser", 69, _traverse)
NOISY_SCANNER = Role("noisy_scanner", 70, _noisy_scan)
BROKEN_LINK_BROWSER = Role("broken_link_browser", 71, _follow_broken_links)


SCENARIOS: Final[dict[str, Scenario]] = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "normal_browsing",
            "Ordinary shoppers and a search engine. Nothing hostile at all.",
            mix=(BROWSER,) * 6 + (BROKEN_LINK_BROWSER, CRAWLER),
        ),
        Scenario(
            "wordpress_scan",
            "Content discovery against a mostly quiet site.",
            mix=(BROWSER,) * 4 + (CRAWLER, SCANNER, NOISY_SCANNER),
        ),
        Scenario(
            "sqli_campaign",
            "Recon, then injection, then one payload that returns data.",
            mix=(BROWSER,) * 4 + (CRAWLER, SCANNER, INJECTOR),
        ),
        Scenario(
            "brute_force",
            "Password guessing against the login endpoint.",
            mix=(BROWSER,) * 5 + (GUESSER,),
        ),
        Scenario(
            "path_traversal",
            "A download parameter walked out of the document root.",
            mix=(BROWSER,) * 5 + (TRAVERSER,),
        ),
        # Ordinary clients outnumber hostile ones heavily, as they do on a real
        # site. It is also the harder test: most of the corpus is traffic that
        # must not be flagged, so a false positive has plenty of chances to
        # appear.
        Scenario(
            "mixed",
            "Everything at once: the case a real investigator is handed.",
            # Several injectors, because one is not enough to measure against:
            # an attacker that pauses between visits emits nothing while it
            # waits, so a single slot yields a few dozen injection requests in
            # a corpus of forty thousand, which is too thin to score.
            mix=(BROWSER,) * 13
            + (BROKEN_LINK_BROWSER,)
            + (CRAWLER, CRAWLER, SCANNER, NOISY_SCANNER, GUESSER, TRAVERSER)
            + (INJECTOR,) * 4,
        ),
    )
}
