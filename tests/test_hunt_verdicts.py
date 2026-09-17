"""Tests for strata.hunt.verdicts: evaluate_verdict + render_hunt_result."""

from __future__ import annotations

from strata.hunt.models import Hunt
from strata.hunt.verdicts import evaluate_verdict, render_hunt_result


def test_insufficient_checked_before_falsifies() -> None:
    namespace = {"n": 1}
    verdict = evaluate_verdict(namespace, insufficient_if="n < 3", falsifies_if="n == 0")
    assert verdict == "INSUFFICIENT"


def test_falsifies_if_true_gives_refuted() -> None:
    namespace = {"n": 0}
    verdict = evaluate_verdict(namespace, insufficient_if="n < 0", falsifies_if="n == 0")
    assert verdict == "REFUTED"


def test_neither_true_gives_supported() -> None:
    namespace = {"n": 10}
    verdict = evaluate_verdict(namespace, insufficient_if="n < 3", falsifies_if="n == 0")
    assert verdict == "SUPPORTED"


def _make_hunt(**overrides) -> Hunt:
    base = {
        "id": "HT01",
        "title": "test hunt",
        "hypothesis": "h",
        "rationale": "r",
        "null_hypothesis": "nh",
        "method": "sql",
        "query": "SELECT 1 AS n",
        "falsifies_if": "n == 0",
        "insufficient_if": "n < 1",
        "telemetry_gap": "a real gap",
    }
    base.update(overrides)
    return Hunt.model_validate(base)


def test_render_hunt_result_shows_id_title_and_verdict() -> None:
    hunt = _make_hunt()
    output = render_hunt_result(hunt, {"n": 1}, "SUPPORTED")
    assert "HT01" in output
    assert "test hunt" in output
    assert "VERDICT: SUPPORTED" in output
    assert "a real gap" in output


def test_render_hunt_result_refuted_and_insufficient_equally_present() -> None:
    hunt = _make_hunt()
    refuted = render_hunt_result(hunt, {"n": 0}, "REFUTED")
    insufficient = render_hunt_result(hunt, {"n": 0}, "INSUFFICIENT")
    assert "VERDICT: REFUTED" in refuted
    assert "VERDICT: INSUFFICIENT" in insufficient


def test_render_hunt_result_multi_row_shows_rows() -> None:
    hunt = _make_hunt()
    namespace = {"n": 2, "rows": [{"product_id": "p1"}, {"product_id": "p2"}]}
    output = render_hunt_result(hunt, namespace, "SUPPORTED")
    assert "p1" in output
    assert "p2" in output
