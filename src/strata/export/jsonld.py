"""Raw JSON-LD graph dump (spec section 8.3): the whole graph, no strata
tooling required to read it -- every node and edge, plain JSON-LD.
"""

from __future__ import annotations

import json
import sqlite3

_CONTEXT = {
    "strata": "https://strata.invalid/ontology#",
    "id": "@id",
    "type": "@type",
    "label": "strata:label",
    "attrs": "strata:attrs",
    "source": "strata:source",
    "target": "strata:target",
    "source_id": "strata:sourceId",
    "note": "strata:note",
}


def build_jsonld(conn: sqlite3.Connection) -> dict:
    """Build a JSON-LD document over the entire graph (every node + edge).

    Args:
        conn: An open sqlite3.Connection from store.get_connection.

    Returns:
        {"@context": {...}, "@graph": [node/edge entries]}.
    """
    graph: list[dict] = []

    for row in conn.execute("SELECT id, type, label, attrs FROM node ORDER BY type, id"):
        attrs = None
        if row["attrs"]:
            try:
                attrs = json.loads(row["attrs"])
            except json.JSONDecodeError:
                attrs = None
        entry = {
            "id": f"strata:{row['id']}",
            "type": f"strata:{row['type']}",
            "label": row["label"],
        }
        if attrs is not None:
            entry["attrs"] = attrs
        graph.append(entry)

    for row in conn.execute(
        "SELECT id, src_id, dst_id, type, source_id, note FROM edge ORDER BY type, src_id, dst_id"
    ):
        entry = {
            "id": f"strata:edge/{row['id']}",
            "type": f"strata:{row['type']}",
            "source": f"strata:{row['src_id']}",
            "target": f"strata:{row['dst_id']}",
            "source_id": row["source_id"],
        }
        if row["note"]:
            entry["note"] = row["note"]
        graph.append(entry)

    return {"@context": _CONTEXT, "@graph": graph}
