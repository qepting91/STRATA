"""Tests for strata.hunt.graph_ops.descendants_within."""

from __future__ import annotations

import networkx as nx

from strata.hunt.graph_ops import descendants_within


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
