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
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from itertools import groupby, islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from logarc.core.event import NormalizedEvent

__all__ = [
    "CrsDetection",
    "CrsUnavailableError",
    "SidecarConfig",
    "binary_name",
    "default_binary",
    "default_rules",
    "host_speaks_for",
    "primary_site_host",
    "run_sidecar",
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

_BATCH: Final = 20_000
"""Records per sidecar invocation. Bounds the pipe buffer and the memory a
single run holds, without paying process startup per request."""


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
        """A digest of the ruleset revision, the conf files, the paranoia level and the host.

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
                f"Build it with:\n"
                f"  cd {_crs_dir()} && go build -o {self.binary.name} .\n"
                f"Cross-compiling for a Windows interpreter:\n"
                f"  GOOS=windows GOARCH=amd64 go build -o crs-sidecar.exe .\n"
                f"Or set {BINARY_ENV} to an existing build."
            )
        if not (self.rules / "rules").is_dir():
            raise CrsUnavailableError(
                f"CRS ruleset not found at {self.rules}. Clone it with:\n"
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


def run_sidecar(
    events: Iterable[NormalizedEvent],
    *,
    config: SidecarConfig | None = None,
) -> list[CrsDetection]:
    """Replay `events` through CRS and return every reported match.

    Events are grouped by source file so a detection can be tied back to the
    line it came from, and each group is sent in batches rather than as one
    write, so a large case never has more than one batch resident at a time.

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
    """
    config = config or SidecarConfig()
    config.check()

    found: list[CrsDetection] = []
    for source_file_id, group in groupby(events, key=_source_of):
        # `group` is only valid until the outer iterator advances, so it is
        # drained here rather than stashed.
        while batch := list(islice(group, _BATCH)):
            found.extend(_invoke(config, batch, source_file_id=source_file_id))
    return found


def _invoke(
    config: SidecarConfig,
    events: Sequence[NormalizedEvent],
    *,
    source_file_id: str,
) -> list[CrsDetection]:
    payload = "\n".join(json.dumps(as_record(event)) for event in events)
    # Fixed argv: the binary path comes from config, never from log content.
    result = subprocess.run(
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
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != 0:
        raise CrsUnavailableError(
            f"crs-sidecar exited {result.returncode}: {result.stderr.strip() or 'no output'}"
        )

    detections: list[CrsDetection] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # The sidecar writes its run summary to stderr, so anything
            # unparseable on stdout is a genuine surprise. Skipped rather than
            # fatal: losing one detection beats losing the whole enrichment.
            continue
        detections.append(CrsDetection.from_json(data, source_file_id=source_file_id))
    return detections
