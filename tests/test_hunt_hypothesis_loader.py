"""Tests for strata.normalize.hunt_hypothesis_loader.load_hunt_hypotheses
against synthetic fixtures (tests/fixtures/hunt_hypotheses,
tests/fixtures/hunt_hypotheses_bad_citation) -- NOT the real
corpus/hunt_hypotheses/*.yaml files, which are authored separately for
citation-accuracy reasons (same discipline as test_corpus_loader.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strata.normalize.hunt_hypothesis_loader import (
    HuntHypothesisCitationNotFoundError,
    HuntHypothesisValidationError,
    load_hunt_hypotheses,
)


def test_load_hunt_hypotheses_valid_fixture(fixtures_dir: Path) -> None:
    hyp_dir = fixtures_dir / "hunt_hypotheses"
    hypotheses = load_hunt_hypotheses(
        hunt_hypotheses_dir=hyp_dir,
        citations_path=fixtures_dir / "hunt_hypotheses_citations.yaml",
    )

    assert "test-group" in hypotheses
    entry = hypotheses["test-group"]
    assert entry.src == "S-TEST-1"
    assert entry.pir_reference.startswith("Illustrative PIR")
    assert len(entry.cmf_notes) == 3
    assert entry.cmf_notes[0].src == "S-TEST-1"
    assert entry.cmf_notes[1].src is None  # optional src, not every note cites
    assert entry.outcome_criteria.proved
    assert entry.outcome_criteria.disproved
    assert entry.outcome_criteria.inconclusive


def test_load_hunt_hypotheses_missing_dir_returns_empty(tmp_path: Path) -> None:
    assert load_hunt_hypotheses(hunt_hypotheses_dir=tmp_path / "nope") == {}


def test_load_hunt_hypotheses_bad_top_level_citation_raises(fixtures_dir: Path) -> None:
    with pytest.raises(HuntHypothesisCitationNotFoundError):
        load_hunt_hypotheses(
            hunt_hypotheses_dir=fixtures_dir / "hunt_hypotheses_bad_citation",
            citations_path=fixtures_dir / "hunt_hypotheses_citations.yaml",
        )


def test_load_hunt_hypotheses_bad_shape_raises(tmp_path: Path) -> None:
    bad_dir = tmp_path / "hunt_hypotheses"
    bad_dir.mkdir()
    (bad_dir / "malformed.yaml").write_text(
        "group_id: x\nhypothesis_statement: y\nunexpected_field: z\n",
        encoding="utf-8",
    )
    (tmp_path / "citations.yaml").write_text("", encoding="utf-8")

    with pytest.raises(HuntHypothesisValidationError):
        load_hunt_hypotheses(
            hunt_hypotheses_dir=bad_dir, citations_path=tmp_path / "citations.yaml"
        )
