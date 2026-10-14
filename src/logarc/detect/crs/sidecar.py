"""Driving the Go sidecar that replays requests through OWASP CRS.

The sidecar is a separate process for one reason: CRS is SecLang, and the only
maintained engines for it are ModSecurity (C) and Coraza (Go). Reimplementing
either in Python would mean reimplementing the transformation chains and
per-`ARGS` targeting that make CRS's rules worth having, which is the whole
argument against copying its patterns instead.

Records go over stdin as pre-parsed JSON rather than raw log lines, so this
project's parsers stay the single source of truth for reading a log. Detections
come back keyed by `(source_file_id, line_no)` — the same pair `EvidenceRef`
uses, because a case can hold several sources and a line number alone would
collide across them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import queue
import subprocess
import sys
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field, replace
from itertools import groupby, islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from concurrent.futures import Future

    from logarc.core.event import NormalizedEvent

__all__ = [
    "AUTO_ENV",
    "CrsDetection",
    "CrsUnavailableError",
    "SidecarConfig",
    "binary_name",
    "default_binary",
    "default_rules",
    "host_speaks_for",
    "primary_site_host",
    "run_sidecar",
    "runs_by_default",
]

#: Where the sidecar lives when nobody says otherwise: `crs/` at the repo root,
#: four levels up from this file.
_REPO_ROOT: Final = Path(__file__).resolve().parents[4]


def _install_root() -> Path:
    """Where `crs/` and `vendor/coreruleset/` are.

    The repository, in a source checkout. In the packaged application they are
    bundled in the same layout under the folder PyInstaller unpacks to, so
    everything below this function reads the same either way.
    """
    bundle = getattr(sys, "_MEIPASS", None)
    if getattr(sys, "frozen", False) and bundle:
        return Path(bundle)
    return _REPO_ROOT


def _crs_dir() -> Path:
    return _install_root() / "crs"


def default_rules() -> Path:
    """The CRS ruleset: a pinned clone in a checkout, a bundled copy when packaged."""
    return _install_root() / "vendor" / "coreruleset"


#: Env override, so a packaged binary elsewhere on disk can be pointed at.
BINARY_ENV: Final = "LOGARC_CRS_BINARY"

#: Set to `off` to stop CRS running by itself on a case that has just been
#: read, in the window and on the command line alike. One switch for both, so a
#: machine where it has no business running is configured once.
AUTO_ENV: Final = "LOGARC_CRS"

_OFF: Final = frozenset({"off", "0", "false", "no"})


def runs_by_default() -> bool:
    """Whether a new case is replayed through CRS without anybody asking.

    Only a clear no turns it off. A misspelt value leaving CRS running costs one
    slower scan; the other way round, it would cost a case its detections with
    nothing on screen saying they were skipped.
    """
    return os.environ.get(AUTO_ENV, "").strip().lower() not in _OFF


_BATCH: Final = 20_000
"""Records per sidecar invocation. Bounds the pipe buffer and the memory a
single run holds, without paying process startup per request."""

#: Most sidecars run side by side when nobody says otherwise.
#:
#: Measured 2026-10-05 on `2026-09-20-medium`'s 73,427 distinct requests: one
#: sidecar 72.3 s, two 39.3 s, four 25.5 s, the same detections, each sidecar
#: holding about 55 MB at its peak. Four was the cap then, the rule `logarc
#: ingest` uses. It is six since 2026-10-06, measured on four cores behind
#: eight threads with `2026-10-06-medium`'s 74,153: four 24.8 s, six 21.0 s,
#: eight 20.9 s — CRS is CPU-bound Go in processes of its own, and unlike
#: ingest it does get something from the second thread on a core. While six
#: ran, a 20 ms timer in a Qt window fired at worst 41.5 ms late (39.7 ms with
#: four), never past 100 ms, so the window stays usable.
#:
#: Profiled the same day: 92% of a sidecar's time is CRS evaluating its rules,
#: half of that Go's `regexp`; `crs/main.go`'s own work — JSON, setting up the
#: transaction — is under 2%, and no setting of the garbage collector moved
#: the time. Running more of them is the lever this side has.
MAX_DEFAULT_WORKERS: Final = 6


def default_workers() -> int:
    """How many sidecars to run when nobody said: the cores there are, at most six.

    `os.cpu_count()` returns `None` when it cannot tell, and that is read as one.
    """
    return min(MAX_DEFAULT_WORKERS, os.cpu_count() or 1)


DEFAULT_WORKERS: Final = default_workers()

_MIN_SHARE: Final = 500
"""Fewest requests worth a sidecar of their own. One starts in about 0.11 s and
then costs about 0.6 ms a request, so below a few hundred the start-up is most
of the work and splitting would make a small batch slower."""

_REMEMBERED: Final = 250_000
"""Distinct requests whose CRS answer is kept, so a repeat is not replayed.

About 120 bytes each — a 16-byte digest and a dict slot, and the answer, which
for nearly every request is the shared empty tuple — so roughly 30 MB when
full. `2026-09-20-medium` has 73,427 distinct requests in 237,278. Full, the
memory is emptied rather than grown: a repeat then costs one more replay, and
no answer is ever wrong."""


class CrsUnavailableError(RuntimeError):
    """The sidecar binary or the ruleset it needs is not present.

    Carries the build instructions rather than only the missing path: this is
    the error a first-time user hits, and a bare "not found" makes an optional
    component look broken instead of unbuilt.
    """


def binary_name() -> str:
    """The sidecar's file name for this interpreter.

    The extension follows the *interpreter's* platform, not the build host's. A
    Windows interpreter cannot spawn an ELF, and this project is developed with
    a Windows venv over a Linux toolchain, so the two genuinely differ. The
    packaging build names the file it bundles from this too, so the two cannot
    disagree.
    """
    return "crs-sidecar.exe" if sys.platform == "win32" else "crs-sidecar"


def default_binary() -> Path:
    """The sidecar path for this interpreter, unless `BINARY_ENV` names another."""
    override = os.environ.get(BINARY_ENV)
    return Path(override) if override else _crs_dir() / binary_name()


def primary_site_host(hosts: Iterable[str]) -> str | None:
    """The one host to give CRS as the site's own, from however many a case names.

    CRS 931130 decides whether a URL in a parameter is off-domain with
    `!@endsWith .%{request_headers.host}`, and Apache does not log the Host
    header, so the sidecar synthesises one. It takes a single value, and
    `endsWith` means `shop.test` already covers `www.shop.test` and
    `cdn.shop.test` — so the right choice is whichever host covers the most of
    the others.

    Hosts that do not cover each other cannot all be the Host header, and the
    ones left out are still read as off-domain by 931130 — which is why
    `host_speaks_for` decides whether its verdicts count, and this only decides
    what to send. The tie is broken by length and then alphabetically so the
    choice is stable: the same case must fingerprint the same way on every run.
    """
    names = sorted({name for name in hosts if name})
    if not names:
        return None

    def covered(candidate: str) -> int:
        return sum(1 for other in names if _covers(candidate, other))

    return min(names, key=lambda name: (-covered(name), len(name), name))


def host_speaks_for(host: str | None, names: Iterable[str]) -> bool:
    """Whether CRS, told `host`, judged a URL to every one of `names` as the site's own.

    The condition for trusting 931130. `host` has to be one the reader named —
    `localhost`, the placeholder every unanswered case was enriched with, is
    not, and nor is a host they have since withdrawn — and it has to cover the
    rest. A Host header holds one name, so a site that also answers to an
    unrelated domain had links to that domain judged foreign by CRS, and the
    reader has already said they are not.
    """
    if not host:
        return False
    named = {name for name in names if name}
    return host in named and all(_covers(host, name) for name in named)


def _covers(host: str, name: str) -> bool:
    """931130's own test, `@endsWith .<host>`: a host covers itself and its subdomains."""
    return name == host or name.endswith("." + host)


#: Raised whenever the sidecar's own code changes what CRS reports for the same
#: rules and settings, so that the fingerprint changes with it. 2 is
#: `crs/paths.go`: until then the Windows build cleaned paths with backslashes
#: and missed every rule that looks for a file path, 104 detections on CRS's
#: regression corpus.
SIDECAR_REVISION: Final = 2


@dataclass(frozen=True, slots=True)
class SidecarConfig:
    """Everything that changes what the sidecar would report.

    Held together so it can be fingerprinted as a unit and written into the case
    manifest: a detection set is only reproducible if the ruleset revision, the
    configuration and the paranoia level are all known.
    """

    binary: Path = field(default_factory=default_binary)
    rules: Path = field(default_factory=default_rules)
    conf: Path = field(default_factory=_crs_dir)
    paranoia: int = 2
    host: str = "localhost"

    def revision(self) -> str | None:
        """The ruleset's git revision, or None if nothing records one.

        A clone answers from `.git`. The packaged application carries the rules
        without their history, so the build writes the revision into a
        `REVISION` file beside them — the fingerprint must still name the
        ruleset that produced a detection, or a report cannot say what it ran.
        """
        head = self.rules / ".git" / "HEAD"
        if not head.exists():
            recorded = self.rules / "REVISION"
            if recorded.exists():
                return recorded.read_text(encoding="utf-8").strip() or None
            return None
        ref = head.read_text(encoding="utf-8").strip()
        if ref.startswith("ref: "):
            target = self.rules / ".git" / ref[5:]
            ref = target.read_text(encoding="utf-8").strip() if target.exists() else ref
        return ref or None

    def fingerprint(self) -> str:
        """A digest of the ruleset revision, the conf files, the paranoia level, the
        host and the sidecar's own revision.

        Recorded beside the native ruleset fingerprint so a report can name
        everything that produced it, and compared on re-runs so that retuning
        invalidates stored detections instead of silently mixing two settings.
        """
        digest = hashlib.sha256()
        digest.update((self.revision() or "unknown").encode())
        for name in ("coraza.conf", "crs-setup.conf"):
            path = self.conf / name
            if path.exists():
                digest.update(path.read_bytes())
        digest.update(str(self.paranoia).encode())
        # The host changes what CRS reports — 931130 compares every URL in a
        # parameter against it — so two cases enriched with different hosts must
        # not claim one configuration.
        digest.update(self.host.encode())
        digest.update(f"sidecar {SIDECAR_REVISION}".encode())
        return digest.hexdigest()[:16]

    def as_config(self) -> dict[str, Any]:
        """The form recorded in the case manifest."""
        return {
            "crs_revision": self.revision(),
            "crs_fingerprint": self.fingerprint(),
            "crs_paranoia_level": self.paranoia,
            # Recorded so the engine can tell whether 931130's verdicts were
            # reached against the site's real name or against a placeholder.
            "crs_host": self.host,
        }

    def check(self) -> None:
        """Raise `CrsUnavailableError` unless both the binary and ruleset are present."""
        if not self.binary.exists():
            # The packaged build ships the sidecar, so reaching this means the
            # copy on disk is damaged or incomplete. Its reader has no Go
            # toolchain and no `crs/` directory, so the build command would send
            # them looking for things that are not there; reinstalling is what
            # actually gets them back.
            if getattr(sys, "frozen", False):
                raise CrsUnavailableError(
                    f"CRS enrichment is not available: this copy of logarc is "
                    f"missing its CRS sidecar ({self.binary}).\n"
                    f"Reinstall the application, or set {BINARY_ENV} to a "
                    f"build you already have.\n"
                    f"Everything else works without it, and every analysis says "
                    f"when CRS was not consulted."
                )
            raise CrsUnavailableError(
                f"CRS sidecar not found at {self.binary}.\n"
                f"Set CRS up with:\n"
                f"  logarc setup-crs\n"
                f"which fetches the pinned ruleset and builds the sidecar, once (it needs git "
                f"and Go 1.25+). Or build it by hand:\n"
                f"  cd {_crs_dir()} && go build -o {self.binary.name} .\n"
                f"Cross-compiling for a Windows interpreter:\n"
                f"  GOOS=windows GOARCH=amd64 go build -o crs-sidecar.exe .\n"
                f"Or set {BINARY_ENV} to an existing build."
            )
        if not (self.rules / "rules").is_dir():
            raise CrsUnavailableError(
                f"CRS ruleset not found at {self.rules}. Set it up with:\n"
                f"  logarc setup-crs\n"
                f"which fetches the revision this project measures against. Or clone it by hand:\n"
                f"  git clone https://github.com/coreruleset/coreruleset.git {self.rules}"
            )


@dataclass(frozen=True, slots=True)
class CrsDetection:
    """One CRS rule matching one request.

    A rule matching in two parameters produces two of these sharing a `rule_id`.
    They are not collapsed, because `transformed_value` is only meaningful
    against the parameter it was taken from.
    """

    source_file_id: str
    line_no: int
    rule_id: int
    severity: str
    msg: str
    matched_var: str
    transformed_value: str
    attack_family: str | None = None
    paranoia_level: int | None = None
    tags: tuple[str, ...] = ()
    capec: tuple[str, ...] = ()

    @property
    def label_id(self) -> str:
        """The form a rule id takes when it reaches an episode: `crs:942100`.

        Prefixed so a reader can tell at a glance which detections came from
        this project's rule packs and which from CRS.
        """
        return f"crs:{self.rule_id}"

    @classmethod
    def from_json(cls, data: Mapping[str, Any], *, source_file_id: str) -> CrsDetection:
        return cls(
            source_file_id=source_file_id,
            line_no=int(data["line_no"]),
            rule_id=int(data["rule_id"]),
            severity=str(data.get("severity") or "unknown"),
            msg=str(data.get("msg") or ""),
            matched_var=str(data.get("matched_var") or ""),
            transformed_value=str(data.get("transformed_value") or ""),
            attack_family=data.get("attack_family") or None,
            paranoia_level=data.get("paranoia_level"),
            tags=tuple(data.get("tags") or ()),
            capec=tuple(data.get("capec") or ()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file_id": self.source_file_id,
            "line_no": self.line_no,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "msg": self.msg,
            "matched_var": self.matched_var,
            "transformed_value": self.transformed_value,
            "attack_family": self.attack_family,
            "paranoia_level": self.paranoia_level,
            "tags": list(self.tags),
            "capec": list(self.capec),
        }


def as_record(event: NormalizedEvent) -> dict[str, Any]:
    """One event in the shape the sidecar reads.

    `raw_target` is the path and query recombined, because CRS parses `ARGS`
    itself and expects the request line as sent. Handing it a pre-split path
    would leave every `ARGS`-targeted rule — most of them — with nothing to
    match against.
    """
    return {
        "line_no": event.evidence.line_no,
        "client_ip": event.client_ip,
        "method": event.method,
        "raw_target": event.target,
        "protocol": event.protocol,
        "status": event.status,
        "referer": event.referer,
        "user_agent": event.user_agent,
    }


def _source_of(event: NormalizedEvent) -> str:
    return event.evidence.source_file_id


def _client_as_crs_reads_it(address: str) -> str:
    """The client address as far as CRS can tell one from another.

    CRS reads `REMOTE_ADDR` in two rules, 905100 and 905110, and both only to
    exempt loopback. So every other address is the same address to it, and
    collapses to one value here. An address it *could* read as loopback keeps
    its own identity — the IPv4-mapped form too, which Go's address matching
    treats as the IPv4 address inside it — and so does anything that does not
    parse, because what CRS makes of that is not worth guessing.

    The mapped form is checked explicitly because `ipaddress` changed its mind
    within a minor version: `::ffff:127.0.0.1` is loopback to CPython 3.11.17
    and 3.12.10, and not to 3.11.4 or 3.12.3, all of which this package admits.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    mapped = getattr(parsed, "ipv4_mapped", None)
    if parsed.is_loopback or (mapped is not None and mapped.is_loopback):
        return address
    return ""


def _replay_key(event: NormalizedEvent) -> bytes:
    """Everything CRS's answer depends on, and nothing else.

    `crs/main.go` opens a fresh transaction for each record and closes it after,
    so nothing carries from one request to the next: equal records get equal
    answers. Built from `as_record` so a field added there is part of the key
    without anybody remembering to add it here — only the line number, which
    CRS never sees, and the client address, reduced as above, are taken out.
    """
    record = as_record(event)
    del record["line_no"]
    record["client_ip"] = _client_as_crs_reads_it(str(record["client_ip"]))
    encoded = json.dumps(record, sort_keys=True).encode("utf-8")
    return hashlib.blake2b(encoded, digest_size=16).digest()


def run_sidecar(
    events: Iterable[NormalizedEvent],
    *,
    config: SidecarConfig | None = None,
    workers: int | None = None,
) -> list[CrsDetection]:
    """Replay `events` through CRS and return every reported match.

    Events are grouped by source file so a detection can be tied back to the
    line it came from, and each group is sent in batches rather than as one
    write, so a large case never has more than two batches resident at a time:
    the one with the sidecars, and the next, being read.

    The grouping is `groupby` over the stream rather than a dict of lists, and
    that difference is the whole point: `EventStore.all_events()` already yields
    in `(source_file_id, line_no)` order, so consecutive grouping sees each
    source exactly once without ever holding the corpus. Collecting into a dict
    first would have read every event into memory before the sidecar started —
    undoing the streaming the store goes to trouble to provide, on the one path
    that reads a whole case.

    Input that is *not* ordered by source is still handled correctly; a source
    that appears in several runs simply costs several invocations, because each
    batch carries the id it was grouped under.

    **Each distinct request is replayed once.** A repeat — the same page, asset
    or call, made again — gets the answer its first occurrence got, under its
    own line and source. On `2026-09-20-medium` that is 73,427 replays instead
    of 237,278. `_replay_key` says what counts as the same.

    **The next batch is read while the last one is replayed**, and its share of
    the work starts as soon as a sidecar comes free, rather than once the
    slowest share of the batch before has finished. Measured on
    `2026-10-06-medium`, doing those one after the other left the sidecars idle
    for 4.2 s of 31.8. So a stop takes effect after up to two batches rather
    than one, and progress counted by what has been read runs up to two
    batches ahead of what has been replayed.

    `workers` is how many sidecars run at once, defaulting to
    `DEFAULT_WORKERS`. It changes how long a run takes and nothing it reports.
    """
    config = config or SidecarConfig()
    config.check()
    workers = workers or DEFAULT_WORKERS

    remembered: dict[bytes, tuple[CrsDetection, ...]] = {}
    found: list[CrsDetection] = []
    # One pool for the whole run, so the sidecars are shared across batches and
    # never more than `workers` of them run at once. Threads rather than
    # processes because the work happens in the sidecars; a thread here only
    # waits on its pipe. The sidecars outlive every share and are closed after
    # the pool, whichever way the run ends.
    with _Sidecars(config, workers) as sidecars:
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            running: _Dispatched | None = None
            for source_file_id, group in groupby(events, key=_source_of):
                # `group` is only valid until the outer iterator advances, so it
                # is drained here rather than stashed.
                while batch := list(islice(group, _BATCH)):
                    ahead = _dispatch(
                        pool, sidecars, batch, source_file_id, remembered, running, workers
                    )
                    if running is not None:
                        found.extend(_settle(running, remembered))
                    running = ahead
            if running is not None:
                found.extend(_settle(running, remembered))
        except BaseException:
            # Shares not yet started would only be thrown away.
            pool.shutdown(wait=True, cancel_futures=True)
            raise
        pool.shutdown(wait=True)
    return found


@dataclass(slots=True)
class _Dispatched:
    """A batch whose new requests are with the sidecars, not yet answered."""

    batch: Sequence[NormalizedEvent]
    keys: list[bytes]
    source_file_id: str
    fresh: dict[bytes, NormalizedEvent]
    """The requests sent, each under the first line it was seen on."""

    known: dict[bytes, tuple[CrsDetection, ...]]
    """Answers already remembered when the batch was sent, copied out because
    settling the batch before this one may empty the memory first."""

    replies: list[Future[list[CrsDetection]]]


def _dispatch(
    pool: ThreadPoolExecutor,
    sidecars: _Sidecars,
    batch: Sequence[NormalizedEvent],
    source_file_id: str,
    remembered: dict[bytes, tuple[CrsDetection, ...]],
    running: _Dispatched | None,
    workers: int,
) -> _Dispatched:
    """Send a batch's new requests to the sidecars, and return without waiting.

    A request is new unless its answer is remembered, or it is already on its
    way in the batch before this one — still running, and settled first.
    """
    keys = [_replay_key(event) for event in batch]
    pending = running.fresh if running is not None else {}
    fresh: dict[bytes, NormalizedEvent] = {}
    known: dict[bytes, tuple[CrsDetection, ...]] = {}
    for key, event in zip(keys, batch, strict=True):
        if key in remembered:
            known[key] = remembered[key]
        elif key not in pending and key not in fresh:
            fresh[key] = event
    replies = _share(pool, sidecars, list(fresh.values()), source_file_id, workers) if fresh else []
    return _Dispatched(batch, keys, source_file_id, fresh, known, replies)


def _share(
    pool: ThreadPoolExecutor,
    sidecars: _Sidecars,
    events: Sequence[NormalizedEvent],
    source_file_id: str,
    workers: int,
) -> list[Future[list[CrsDetection]]]:
    """The requests split between up to `workers` sidecars.

    Each request goes to exactly one of them, and a detection names the line
    it came from, so the answers merge back by line whatever order the
    sidecars finish in.
    """
    shares = max(1, min(workers, len(events) // _MIN_SHARE))
    size = -(-len(events) // shares)
    return [
        pool.submit(sidecars.answer, events[start : start + size], source_file_id)
        for start in range(0, len(events), size)
    ]


def _settle(
    dispatched: _Dispatched,
    remembered: dict[bytes, tuple[CrsDetection, ...]],
) -> list[CrsDetection]:
    """Wait for a batch's answers and give every line in it its own.

    Answers come back in line order, fresh and remembered interleaved, which is
    the order the sidecar itself reports in. A request that was on its way in
    the batch before is answered from memory: that batch was settled first.
    """
    by_line: dict[int, list[CrsDetection]] = {}
    for reply in dispatched.replies:
        for detection in reply.result():
            by_line.setdefault(detection.line_no, []).append(detection)
    answers = {
        key: tuple(by_line.get(event.evidence.line_no, ()))
        for key, event in dispatched.fresh.items()
    }

    source_file_id = dispatched.source_file_id
    found: list[CrsDetection] = []
    for key, event in zip(dispatched.keys, dispatched.batch, strict=True):
        line_no = event.evidence.line_no
        if key in answers:
            answer = answers[key]
        elif key in dispatched.known:
            answer = dispatched.known[key]
        else:
            answer = remembered[key]
        for one in answer:
            if one.line_no == line_no and one.source_file_id == source_file_id:
                found.append(one)
            else:
                found.append(replace(one, line_no=line_no, source_file_id=source_file_id))

    if len(remembered) + len(answers) > _REMEMBERED:
        remembered.clear()
    remembered.update(answers)
    return found


#: How long a sidecar may take to exit once its input is closed, before it is
#: killed. Every share has been answered by then, so it has only its summary
#: left to write.
_CLOSE_SECONDS: Final = 30


class _Sidecar:
    """One sidecar process, sent one share after another for a whole run.

    Each share is followed by `{"flush": N}`, which the sidecar answers with
    `{"flushed": N}` once everything before it is answered (`crs/main.go`). Its
    stdout and stderr are drained by threads of their own, so a share larger
    than a pipe holds is written while its answers flow back rather than
    deadlocking against them.

    There is no time limit on a share, as there was none on the process that
    ran one before: CRS evaluating a request is CPU-bound and finite, and a
    limit would have to be a guess about the slowest machine.
    """

    def __init__(self, config: SidecarConfig) -> None:
        # Fixed argv: the binary path comes from config, never from log content.
        self._process = subprocess.Popen(
            [
                str(config.binary),
                "--rules",
                str(config.rules),
                "--conf",
                str(config.conf),
                "--paranoia",
                str(config.paranoia),
                "--host",
                config.host,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._answers: queue.Queue[str | None] = queue.Queue()
        # The last of what it said on stderr: its summary, or why it stopped.
        self._said: deque[str] = deque(maxlen=50)
        self._shares = 0
        self._threads = [
            threading.Thread(target=self._drain_stdout, daemon=True),
            threading.Thread(target=self._drain_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _drain_stdout(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._answers.put(line)
        self._answers.put(None)

    def _drain_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._said.append(line.rstrip())

    def answer(self, events: Sequence[NormalizedEvent], source_file_id: str) -> list[CrsDetection]:
        self._shares += 1
        marker = self._shares
        payload = "".join(json.dumps(as_record(event)) + "\n" for event in events)
        payload += json.dumps({"flush": marker}) + "\n"
        assert self._process.stdin is not None
        try:
            self._process.stdin.write(payload)
            self._process.stdin.flush()
        except OSError:
            raise self._failed() from None

        detections: list[CrsDetection] = []
        while True:
            line = self._answers.get()
            if line is None:
                # Left for whoever asks next: an output that has ended stays
                # ended, and a share handed this sidecar after it died would
                # otherwise wait for an answer forever. Ending before the share
                # was answered means it exited, and an answer cut short must not
                # read as a share with nothing in it.
                self._answers.put(None)
                raise self._failed()
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # The sidecar writes its run summary to stderr, so anything
                # unparseable on stdout is a genuine surprise. Skipped rather
                # than fatal: losing one detection beats losing the enrichment.
                continue
            if "flushed" in data:
                if data["flushed"] == marker:
                    return detections
                # Nothing it says after this can be trusted to the right lines.
                self._process.kill()
                raise CrsUnavailableError(
                    f"crs-sidecar is out of step: it answered share {data['flushed']} "
                    f"while share {marker} was waiting"
                )
            detections.append(CrsDetection.from_json(data, source_file_id=source_file_id))

    def _failed(self) -> CrsUnavailableError:
        try:
            code = self._process.wait(timeout=_CLOSE_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            code = self._process.wait()
        self._threads[1].join(timeout=_CLOSE_SECONDS)
        said = "\n".join(self._said).strip()
        return CrsUnavailableError(f"crs-sidecar exited {code}: {said or 'no output'}")

    def close(self) -> None:
        """Close its input, let it exit, and kill it only if it will not."""
        assert self._process.stdin is not None
        with suppress(OSError):
            self._process.stdin.close()
        try:
            self._process.wait(timeout=_CLOSE_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        for thread in self._threads:
            thread.join(timeout=_CLOSE_SECONDS)
        for stream in (self._process.stdout, self._process.stderr):
            if stream is not None:
                stream.close()


class _Sidecars:
    """Up to `limit` sidecars for one run, started only when a share needs one.

    A share takes an idle sidecar, or starts one if fewer than `limit` have
    been, and gives it back when it is done. One that failed is given back too:
    the run is failing, and a share that takes it is refused at once rather
    than left waiting for an answer. Closing the pool closes every sidecar it
    started.
    """

    def __init__(self, config: SidecarConfig, limit: int) -> None:
        self._config = config
        self._limit = limit
        self._idle: queue.Queue[_Sidecar] = queue.Queue()
        self._started: list[_Sidecar] = []
        self._lock = threading.Lock()

    def __enter__(self) -> _Sidecars:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def answer(self, events: Sequence[NormalizedEvent], source_file_id: str) -> list[CrsDetection]:
        sidecar = self._take()
        try:
            return sidecar.answer(events, source_file_id)
        finally:
            self._idle.put(sidecar)

    def _take(self) -> _Sidecar:
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if len(self._started) < self._limit:
                sidecar = _Sidecar(self._config)
                self._started.append(sidecar)
                return sidecar
        return self._idle.get()

    def close(self) -> None:
        for sidecar in self._started:
            sidecar.close()
