"""Tests for strata.hunt.models's method/field validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from strata.hunt.models import Hunt

_BASE = {
    "id": "HT01",
    "title": "test hunt",
    "hypothesis": "h",
    "rationale": "r",
    "null_hypothesis": "nh",
    "falsifies_if": "n == 0",
    "insufficient_if": "n < 1",
    "telemetry_gap": "none",
}


def test_sql_hunt_requires_query() -> None:
    with pytest.raises(ValidationError):
        Hunt.model_validate({**_BASE, "method": "sql"})


def test_sql_hunt_rejects_python_fn() -> None:
    with pytest.raises(ValidationError):
        Hunt.model_validate(
            {**_BASE, "method": "sql", "query": "SELECT 1", "python_fn": "whatever"}
        )


def test_valid_sql_hunt() -> None:
    hunt = Hunt.model_validate({**_BASE, "method": "sql", "query": "SELECT 1 AS n"})
    assert hunt.method == "sql"
    assert hunt.graph_op is None
    assert hunt.python_fn is None


def test_valid_python_hunt() -> None:
    hunt = Hunt.model_validate({**_BASE, "method": "python", "python_fn": "some_fn"})
    assert hunt.query is None


def test_valid_graph_hunt() -> None:
    hunt = Hunt.model_validate(
        {
            **_BASE,
            "method": "graph",
            "graph_op": {
                "projection": {"node_types": ["group"], "edge_types": ["uses"]},
                "fn": "descendants_within",
                "args": {"source": "x", "depth": 1, "via": ["uses"]},
            },
        }
    )
    assert hunt.graph_op is not None
    assert hunt.graph_op.fn == "descendants_within"
