"""What the window says when a case's CRS results were made by an older CRS.

Free of Qt, like the format and quarantine wording beside it. The judgement is
the part that can mislead: a strip that fires on every case trains the reader
to close it, and one that never fires leaves a Windows case from before
2026-10-14 missing every file-path attack CRS has learned to see since.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from zodiarc.detect.crs import SidecarConfig
from zodiarc.gui.crs_notice import partial_crs_notice, stale_crs_notice

if TYPE_CHECKING:
    from pathlib import Path


def _config(root: Path, **changes: object) -> SidecarConfig:
    return SidecarConfig(rules=root, conf=root, **changes)  # type: ignore[arg-type]


def test_a_case_never_checked_with_crs_says_nothing(tmp_path: Path) -> None:
    assert stale_crs_notice(None, _config(tmp_path)) is None


def test_a_case_checked_by_the_crs_here_says_nothing(tmp_path: Path) -> None:
    now = _config(tmp_path)

    assert stale_crs_notice(now.as_config(), now) is None


def test_a_case_checked_by_an_older_crs_says_so(tmp_path: Path) -> None:
    """The configuration moved since: here its file, as a CRS upgrade or the
    sidecar's own fix would move the fingerprint."""
    (tmp_path / "crs-setup.conf").write_text("# before\n", encoding="utf-8")
    then = _config(tmp_path).as_config()
    (tmp_path / "crs-setup.conf").write_text("# after\n", encoding="utf-8")

    notice = stale_crs_notice(then, _config(tmp_path))

    assert notice is not None
    assert "older" in notice.headline
    assert "again" in notice.detail


def test_an_older_crs_never_interrupts(tmp_path: Path) -> None:
    """The case is intact and its other findings stand. A strip, not a dialog."""
    (tmp_path / "crs-setup.conf").write_text("# before\n", encoding="utf-8")
    then = _config(tmp_path).as_config()
    (tmp_path / "crs-setup.conf").write_text("# after\n", encoding="utf-8")

    notice = stale_crs_notice(then, _config(tmp_path))

    assert notice is not None
    assert not notice.is_blocking


def test_without_crs_here_there_is_nothing_to_offer(tmp_path: Path) -> None:
    """A strip asking to run CRS again on a computer that cannot run it is a
    button that only fails."""
    (tmp_path / "crs-setup.conf").write_text("# before\n", encoding="utf-8")
    then = _config(tmp_path).as_config()

    assert stale_crs_notice(then, None) is None


def test_a_case_checked_at_another_paranoia_level_says_nothing(tmp_path: Path) -> None:
    """`zodiarc-dev enrich --paranoia 3` is a choice, not an old version. Running
    it again from the window would quietly undo it at the default level."""
    then = _config(tmp_path, paranoia=3).as_config()

    assert stale_crs_notice(then, _config(tmp_path)) is None


def test_a_complete_crs_run_says_nothing() -> None:
    assert partial_crs_notice(None) is None


def test_a_stopped_crs_run_says_how_far_it_got() -> None:
    """The requests it never reached carry no CRS finding, which is also what a
    request it read and passed carries. Only the case can tell them apart."""
    notice = partial_crs_notice((2, 4))

    assert notice is not None
    assert "part" in notice.headline
    assert "2 of 4 requests" in notice.detail
    assert not notice.is_blocking
