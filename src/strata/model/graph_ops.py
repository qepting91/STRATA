"""Graph-traversal utilities over the node/edge tables.

Used by `strata graph show` (a bounded capability-traversal viewer) and
by the Collection Health page's rendered handoff-model graph
(`ui/data.py::load_handoff_projection`) -- both want the same
group/tool/vuln/product projection over hands_off_to/uses/exploits
edges, not two independently-drifting queries.
"""

from __future__ import annotations

import sqlite3

import networkx as nx


def build_projection(
    conn: sqlite3.Connection, node_types: list[str], edge_types: list[str]
) -> nx.DiGraph:
    """Build a NetworkX DiGraph over the node/edge tables, filtered to types.

    Nodes get a "type" attribute; edges get a "type" attribute. A node
    referenced by a qualifying edge but not itself of a declared node type
    is still added (defensively) so traversal never silently drops a real
    edge -- its type attribute is looked up from the node table directly
    rather than assumed.
    """
    graph = nx.DiGraph()

    node_placeholders = ",".join("?" for _ in node_types)
    node_rows = conn.execute(
        f"SELECT id, type FROM node WHERE type IN ({node_placeholders})",
        node_types,
    ).fetchall()
    for row in node_rows:
        graph.add_node(row["id"], type=row["type"])

    edge_placeholders = ",".join("?" for _ in edge_types)
    edge_rows = conn.execute(
        f"SELECT src_id, dst_id, type FROM edge WHERE type IN ({edge_placeholders})",
        edge_types,
    ).fetchall()

    node_type_cache: dict[str, str] = {}
    for row in edge_rows:
        for node_id in (row["src_id"], row["dst_id"]):
            if node_id in graph:
                continue
            if node_id not in node_type_cache:
                lookup = conn.execute(
                    "SELECT type FROM node WHERE id = ?", (node_id,)
                ).fetchone()
                node_type_cache[node_id] = lookup["type"] if lookup else "unknown"
            graph.add_node(node_id, type=node_type_cache[node_id])
        graph.add_edge(row["src_id"], row["dst_id"], type=row["type"])

    return graph


def descendants_within(G: nx.DiGraph, source: str, depth: int, via: list[str]) -> dict:
    """BFS from `source` through only edges whose type is in `via`, up to `depth` hops.

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
