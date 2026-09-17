"""Streamlit UI tests: streamlit.testing.v1.AppTest driving every page
headlessly against the real local database (spec section 15.6's testing
approach, adapted to the real DB per this task's explicit instruction).

Each page/app test asserts:
  - the page renders without raising (at.exception is empty), and
  - the Hunt Board page shows the real mixed verdict mix (at least one
    non-SUPPORTED card) -- trivially true given the real board (4
    SUPPORTED, 1 REFUTED, 5 INSUFFICIENT), but asserted for real rather
    than assumed.

Skipped entirely if data/strata.db does not exist in this environment
(e.g. a from-scratch checkout that has never run `strata collect`/
`strata build`) -- these are the one place in the suite that
deliberately exercises the real database rather than a synthetic
fixture, per this task's explicit instruction.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DB_PATH = _REPO_ROOT / "data" / "strata.db"
_UI_ROOT = _REPO_ROOT / "src" / "strata" / "ui"

pytestmark = pytest.mark.skipif(
    not _DB_PATH.exists(),
    reason="data/strata.db not present -- run `strata collect`/`strata build` first",
)


@pytest.fixture(autouse=True)
def _real_db_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the UI's data.py at the real database for every test here."""
    monkeypatch.setenv("STRATA_DB_PATH", str(_DB_PATH))


def _run_page(relative_path: str) -> AppTest:
    at = AppTest.from_file(str(_UI_ROOT / relative_path), default_timeout=60)
    # AppTest resolves relative paths (hunts/, config/, corpus/,
    # tests/fixtures/) against the process cwd, not the script's own
    # directory -- run from the real repo root so those resolve exactly
    # as they do for `strata ui` / `strata hunt run` from the repo root.
    old_cwd = Path.cwd()
    os.chdir(_REPO_ROOT)
    try:
        at.run()
    finally:
        os.chdir(old_cwd)
    return at


def test_app_entrypoint_renders() -> None:
    at = _run_page("app.py")
    assert not at.exception


def test_hunt_board_renders_and_shows_mixed_verdicts() -> None:
    at = _run_page("pages/1_Hunt_Board.py")
    assert not at.exception

    metrics = {m.label: m.value for m in at.metric}
    assert "SUPPORTED" in metrics
    assert "REFUTED" in metrics
    assert "INSUFFICIENT" in metrics

    # The real board (per Week 4's own verdict table): 4 SUPPORTED,
    # 1 REFUTED, 5 INSUFFICIENT -- at least one non-SUPPORTED card is
    # what makes this a real hunt board, not a curated all-green one.
    non_supported = int(metrics["REFUTED"]) + int(metrics["INSUFFICIENT"])
    assert non_supported >= 1


def test_threat_groups_renders() -> None:
    at = _run_page("pages/2_Threat_Groups.py")
    assert not at.exception


def test_weaponization_timeline_renders_on_near_empty_data() -> None:
    at = _run_page("pages/3_Weaponization_Timeline.py")
    assert not at.exception


def test_protocol_cves_renders() -> None:
    at = _run_page("pages/4_Protocol_CVEs.py")
    assert not at.exception


def test_visibility_gaps_renders() -> None:
    at = _run_page("pages/5_Visibility_Gaps.py")
    assert not at.exception


def test_collection_health_renders() -> None:
    at = _run_page("pages/6_Collection_Health.py")
    assert not at.exception
