"""Hunt loader + dispatcher (spec section 7.1/7.3).

load_hunt(path) parses and validates one hunts/*.yaml file into a Hunt.
run_hunt(conn, hunt) dispatches by hunt.method to a namespace dict that
hunt.falsifies_if / hunt.insufficient_if get evaluated against.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import networkx as nx
import yaml

from strata.hunt.graph_ops import GRAPH_OPS
from strata.hunt.methods import METHODS
from strata.hunt.models import Hunt


@dataclass
class HuntResult:
    """The outcome of running one hunt: the hunt itself plus its namespace."""

    hunt: Hunt
    namespace: dict


def load_hunt(path: Path | str) -> Hunt:
    """Load and validate one hunt YAML file into a Hunt model.

    Args:
        path: Path to a hunts/H0XX-*.yaml file.

    Returns:
        A validated Hunt instance.

    Raises:
        pydantic.ValidationError: If the YAML is missing required fields or
            declares a method/field mismatch (see Hunt._check_method_field_pairing).
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Hunt.model_validate(data)


def load_all_hunts(hunts_dir: Path | str = "hunts") -> list[Hunt]:
    """Load every hunts/*.yaml file, sorted by id."""
    paths = sorted(Path(hunts_dir).glob("*.yaml"))
    hunts = [load_hunt(p) for p in paths]
    hunts.sort(key=lambda h: h.id)
    return hunts


def _run_sql_hunt(conn: sqlite3.Connection, hunt: Hunt) -> dict:
    """Run a method=sql hunt query (read-only; hunt queries are static/curated).

    If the query returns exactly one row, its named columns are exposed
    directly as evaluation variables (e.g. n, pct_patched_before_kev),
    plus a "rows" key for uniformity. If it returns zero or more than one
    row, the namespace is {"n": <row count>, "rows": [<row dicts>]} --
    the hunt's own query is expected to use GROUP BY/HAVING to pre-shape
    what it needs (e.g. H001's "products with >=2 distinct exploiting
    groups" join), not the runner doing generic statistics over an
    arbitrary result set.
    """
    assert hunt.query is not None
    cur = conn.execute(hunt.query)
    columns = [d[0] for d in cur.description]
    rows = [dict(zip(columns, r, strict=True)) for r in cur.fetchall()]

    if len(rows) == 1:
        namespace = dict(rows[0])
        namespace["rows"] = rows
        return namespace

    return {"n": len(rows), "rows": rows}


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


def _run_graph_hunt(conn: sqlite3.Connection, hunt: Hunt) -> dict:
    """Run a method=graph hunt: build the declared projection, call the named op."""
    assert hunt.graph_op is not None
    projection = hunt.graph_op.projection
    graph = build_projection(conn, projection.node_types, projection.edge_types)
    fn = GRAPH_OPS[hunt.graph_op.fn]
    return fn(graph, **hunt.graph_op.args)


def _run_python_hunt(conn: sqlite3.Connection, hunt: Hunt) -> dict:
    """Run a method=python hunt: dispatch to the registered function in hunt/methods.py."""
    assert hunt.python_fn is not None
    fn = METHODS[hunt.python_fn]
    return fn(conn)


def run_hunt(conn: sqlite3.Connection, hunt: Hunt) -> HuntResult:
    """Execute a hunt and return its evaluation namespace.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.
        hunt: A validated Hunt (from load_hunt).

    Returns:
        A HuntResult carrying the hunt and its namespace dict.

    Raises:
        KeyError: If a graph/python hunt names an unregistered fn.
    """
    if hunt.method == "sql":
        namespace = _run_sql_hunt(conn, hunt)
    elif hunt.method == "graph":
        namespace = _run_graph_hunt(conn, hunt)
    else:
        namespace = _run_python_hunt(conn, hunt)

    return HuntResult(hunt=hunt, namespace=namespace)
