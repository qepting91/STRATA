"""Tests for strata.model.graph_ops: build_projection + descendants_within.

Used by `strata graph show` and the Collection Health page's rendered
handoff-model graph.
"""

from __future__ import annotations

import networkx as nx

from strata.model import store
from strata.model.graph_ops import build_projection, descendants_within


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


def test_build_projection_filters_types(db_conn) -> None:
    _seed_small_graph(db_conn)
    graph = build_projection(db_conn, ["group"], ["hands_off_to"])
    assert set(graph.nodes) >= {"group-a", "group-b"}
    assert graph.has_edge("group-a", "group-b")
    assert graph["group-a"]["group-b"]["type"] == "hands_off_to"


def test_build_projection_adds_edge_endpoints_outside_declared_node_types(db_conn) -> None:
    _seed_small_graph(db_conn)
    graph = build_projection(db_conn, ["group"], ["hands_off_to", "uses"])
    assert "tool-x" in graph
    assert graph.nodes["tool-x"]["type"] == "tool"


def _graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("a", type="group")
    g.add_node("b", type="group")
    g.add_node("c", type="tool")
    g.add_node("d", type="vuln")
    g.add_edge("a", "b", type="hands_off_to")
    g.add_edge("b", "c", type="uses")
    g.add_edge("c", "d", type="irrelevant")
    return g


def test_descendants_within_multi_hop() -> None:
    g = _graph()
    result = descendants_within(g, source="a", depth=2, via=["hands_off_to", "uses"])
    assert result["source_present"] is True
    assert result["n"] == 2
    assert set(result["reachable_nodes"]) == {"b", "c"}
    assert result["by_type"] == {"group": 1, "tool": 1}


def test_descendants_within_depth_limits_traversal() -> None:
    g = _graph()
    result = descendants_within(g, source="a", depth=1, via=["hands_off_to", "uses"])
    assert result["n"] == 1
    assert result["reachable_nodes"] == ["b"]


def test_descendants_within_ignores_wrong_edge_type() -> None:
    g = _graph()
    result = descendants_within(g, source="c", depth=2, via=["hands_off_to", "uses"])
    assert result["n"] == 0
    assert result["source_present"] is True


def test_descendants_within_missing_source() -> None:
    g = _graph()
    result = descendants_within(g, source="zzz", depth=2, via=["uses"])
    assert result["source_present"] is False
    assert result["n"] == 0
