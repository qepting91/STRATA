"""Named NetworkX graph operations for `method: graph` hunts (spec section 7.1/7.2).

Each function takes a `networkx.DiGraph` projection (built by
`hunt/runner.py`'s `build_projection`, filtered to a hunt's declared
`node_types`/`edge_types`) plus keyword args from the hunt YAML's
`graph_op.args`, and returns a plain dict usable as a `simpleeval`
evaluation namespace.
"""

from __future__ import annotations

import networkx as nx


def descendants_within(G: nx.DiGraph, source: str, depth: int, via: list[str]) -> dict:
    """BFS from `source` through only edges whose type is in `via`, up to `depth` hops.

    This is H009's flagship traversal: "given a Stage 1 group, what bounded
    Stage 2 capability set does the graph predict?" -- e.g. source=sylvanite,
    depth=2-3, via=[hands_off_to, uses, exploits] reaches voltzite at hop 1
    (via hands_off_to), then whatever voltzite itself uses/exploits at hop 2
    (which may legitimately be nothing -- voltzite has no `uses`/`exploits`
    edges of its own in the real corpus as of Week 3; that is a real,
    honestly-reported finding, not a bug).

    Args:
        G: A NetworkX DiGraph projection with a `type` attribute on every
            node and edge.
        source: The starting node id. If absent from G, returns an empty
            result with `source_present: False` rather than raising.
        depth: Maximum number of hops to traverse.
        via: Edge types allowed to be traversed.

    Returns:
        {"reachable_nodes": [...], "n": <count>, "by_type": {type: count},
         "source_present": bool} -- reachable_nodes excludes source itself.
    """
    if source not in G:
        return {"reachable_nodes": [], "n": 0, "by_type": {}, "source_present": False}

    visited: set[str] = set()
    frontier: set[str] = {source}
    via_set = set(via)

    for _ in range(depth):
        next_frontier: set[str] = set()
        for node in frontier:
            for _, dst, data in G.out_edges(node, data=True):
                if data.get("type") in via_set and dst != source and dst not in visited:
                    next_frontier.add(dst)
        if not next_frontier:
            break
        visited |= next_frontier
        frontier = next_frontier

    by_type: dict[str, int] = {}
    for node_id in visited:
        node_type = G.nodes[node_id].get("type", "unknown")
        by_type[node_type] = by_type.get(node_type, 0) + 1

    return {
        "reachable_nodes": sorted(visited),
        "n": len(visited),
        "by_type": by_type,
        "source_present": True,
    }


GRAPH_OPS = {
    "descendants_within": descendants_within,
}
