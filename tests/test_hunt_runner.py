"""Tests for strata.hunt.runner: sql/graph/python dispatch against fixture DBs."""

from __future__ import annotations

from strata.hunt.models import GraphOp, GraphProjection, Hunt
from strata.hunt.runner import build_projection, run_hunt
from strata.hunt.verdicts import evaluate_verdict
from strata.model import store


def _seed_small_graph(conn) -> None:
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_source(conn, id="s-1", name="test", url=None, fetched_at=fetched_at)
    for gid in ("group-a", "group-b"):
        store.insert_node(conn, id=gid, type="group", label=gid, attrs=None, created_at=fetched_at)
    store.insert_node(
        conn, id="tool-x", type="tool", label="tool-x", attrs=None, created_at=fetched_at
    )
    store.insert_edge(
        conn, id="e-1", src_id="group-a", dst_id="group-b",
        type="hands_off_to", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e-2", src_id="group-b", dst_id="tool-x",
        type="uses", source_id="s-1",
    )


def _base_kwargs() -> dict:
    return {
        "id": "HT01",
        "title": "test",
        "hypothesis": "h",
        "rationale": "r",
        "null_hypothesis": "nh",
        "telemetry_gap": "none",
    }


def test_run_sql_hunt_single_row_exposes_columns(db_conn) -> None:
    _seed_small_graph(db_conn)
    hunt = Hunt.model_validate(
        {
            **_base_kwargs(),
            "method": "sql",
            "query": "SELECT COUNT(*) AS n FROM node WHERE type = 'group'",
            "falsifies_if": "n == 0",
            "insufficient_if": "n < 1",
        }
    )
    result = run_hunt(db_conn, hunt)
    assert result.namespace["n"] == 2
    verdict = evaluate_verdict(result.namespace, hunt.insufficient_if, hunt.falsifies_if)
    assert verdict == "SUPPORTED"


def test_run_sql_hunt_multi_row_exposes_n_and_rows(db_conn) -> None:
    _seed_small_graph(db_conn)
    hunt = Hunt.model_validate(
        {
            **_base_kwargs(),
            "method": "sql",
            "query": "SELECT id FROM node WHERE type = 'group'",
            "falsifies_if": "n == 0",
            "insufficient_if": "n < 1",
        }
    )
    result = run_hunt(db_conn, hunt)
    assert result.namespace["n"] == 2
    assert len(result.namespace["rows"]) == 2


def test_run_sql_hunt_refuted_verdict_on_zero_rows(db_conn) -> None:
    # No exploits edges seeded at all -> the query legitimately returns 0 rows.
    _seed_small_graph(db_conn)
    hunt = Hunt.model_validate(
        {
            **_base_kwargs(),
            "method": "sql",
            "query": "SELECT id FROM node WHERE type = 'vuln'",
            "falsifies_if": "n == 0",
            "insufficient_if": "n < 0",
        }
    )
    result = run_hunt(db_conn, hunt)
    verdict = evaluate_verdict(result.namespace, hunt.insufficient_if, hunt.falsifies_if)
    assert verdict == "REFUTED"


def test_run_sql_hunt_insufficient_verdict(db_conn) -> None:
    _seed_small_graph(db_conn)
    hunt = Hunt.model_validate(
        {
            **_base_kwargs(),
            "method": "sql",
            "query": "SELECT COUNT(*) AS n FROM node WHERE type = 'group'",
            "falsifies_if": "n == 0",
            "insufficient_if": "n < 100",
        }
    )
    result = run_hunt(db_conn, hunt)
    verdict = evaluate_verdict(result.namespace, hunt.insufficient_if, hunt.falsifies_if)
    assert verdict == "INSUFFICIENT"


def test_build_projection_filters_types(db_conn) -> None:
    _seed_small_graph(db_conn)
    graph = build_projection(db_conn, ["group"], ["hands_off_to"])
    assert set(graph.nodes) >= {"group-a", "group-b"}
    assert graph.has_edge("group-a", "group-b")
    assert graph["group-a"]["group-b"]["type"] == "hands_off_to"


def test_run_graph_hunt(db_conn) -> None:
    _seed_small_graph(db_conn)
    hunt = Hunt.model_validate(
        {
            **_base_kwargs(),
            "method": "graph",
            "graph_op": GraphOp(
                projection=GraphProjection(
                    node_types=["group", "tool"], edge_types=["hands_off_to", "uses"]
                ),
                fn="descendants_within",
                args={"source": "group-a", "depth": 2, "via": ["hands_off_to", "uses"]},
            ),
            "falsifies_if": "n == 0",
            "insufficient_if": "n < 0",
        }
    )
    result = run_hunt(db_conn, hunt)
    assert result.namespace["n"] == 2
    assert set(result.namespace["reachable_nodes"]) == {"group-b", "tool-x"}


def test_run_python_hunt_dispatches_registered_fn(db_conn, monkeypatch) -> None:
    from strata.hunt import runner as runner_module

    monkeypatch.setitem(runner_module.METHODS, "noop_fn", lambda conn: {"n": 42})
    hunt = Hunt.model_validate(
        {
            **_base_kwargs(),
            "method": "python",
            "python_fn": "noop_fn",
            "falsifies_if": "n == 0",
            "insufficient_if": "n < 0",
        }
    )
    result = run_hunt(db_conn, hunt)
    assert result.namespace == {"n": 42}
