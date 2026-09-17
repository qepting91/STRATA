"""Tests for strata.report.render against the real local database.

These deliberately run against ``data/strata.db`` (the real graph built
by Weeks 1-3's `strata collect`/`strata build`), not a synthetic fixture
-- the point is to prove the generated report reflects the actual mixed
hunt board (SUPPORTED + REFUTED + INSUFFICIENT), not just a happy-path
fixture. Skipped if the real database is not present (e.g. a fresh clone
that hasn't run `strata collect`/`strata build` yet).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strata.model import store
from strata.report.render import render_report, write_report

_REAL_DB_PATH = Path("data/strata.db")
_HUNT_IDS = [f"H{n:03d}" for n in range(1, 11)]

pytestmark = pytest.mark.skipif(
    not _REAL_DB_PATH.exists(),
    reason="real data/strata.db not present -- run `strata collect --source all` + "
    "`strata build` first",
)


@pytest.fixture
def real_conn():
    conn = store.get_connection(_REAL_DB_PATH)
    yield conn
    conn.close()


def test_render_report_contains_all_ten_hunt_ids_and_mixed_verdicts(real_conn) -> None:
    text = render_report(real_conn)

    for hunt_id in _HUNT_IDS:
        assert hunt_id in text, f"{hunt_id} missing from generated report"

    assert "REFUTED" in text
    assert "INSUFFICIENT" in text
    assert "SUPPORTED" in text

    # Non-trivial length: a real 7-section report, not an empty/stub render.
    assert len(text) > 4000

    # All 7 spec section headings present.
    for heading in [
        "## 1. Key judgements",
        "## 2. Scope and method",
        "## 3. Findings",
        "## 4. Capability handoff model",
        "## 5. Visibility gaps",
        "## 6. Confidence and limitations",
        "## 7. Appendix",
    ]:
        assert heading in text


def test_write_report_creates_real_file(real_conn, tmp_path) -> None:
    out_path = write_report(real_conn, out_dir=str(tmp_path))

    assert out_path.exists()
    assert out_path.name.endswith("-ot-capability-assessment.md")
    text = out_path.read_text(encoding="utf-8")
    assert len(text) > 4000
    for hunt_id in _HUNT_IDS:
        assert hunt_id in text
    assert "REFUTED" in text
    assert "INSUFFICIENT" in text
