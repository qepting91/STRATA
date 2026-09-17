"""Tests for strata.export.jsonld."""

from __future__ import annotations

import json

from strata.export.jsonld import build_jsonld
from strata.model import store

_FETCHED = "2026-01-01T00:00:00Z"


def _seed(conn) -> None:
    store.insert_source(conn, id="s-1", name="test", url=None, fetched_at=_FETCHED)
    store.insert_node(
        conn, id="group-a", type="group", label="GROUP A",
        attrs=json.dumps({"role": "iab"}), created_at=_FETCHED,
    )
    store.insert_node(
        conn, id="group-b", type="group", label="GROUP B", attrs=None, created_at=_FETCHED
    )
    store.insert_edge(
        conn, id="e1", src_id="group-a", dst_id="group-b",
        type="hands_off_to", source_id="s-1", note="high confidence",
    )


def test_build_jsonld_has_context_and_graph(db_conn) -> None:
    _seed(db_conn)
    doc = build_jsonld(db_conn)
    assert "@context" in doc
    assert "@graph" in doc
    ids = {entry["id"] for entry in doc["@graph"]}
    assert "strata:group-a" in ids
    assert "strata:group-b" in ids

    edge_entries = [e for e in doc["@graph"] if e["type"] == "strata:hands_off_to"]
    assert len(edge_entries) == 1
    assert edge_entries[0]["source"] == "strata:group-a"
    assert edge_entries[0]["target"] == "strata:group-b"
    assert edge_entries[0]["note"] == "high confidence"


def test_build_jsonld_is_json_serializable(db_conn) -> None:
    _seed(db_conn)
    doc = build_jsonld(db_conn)
    text = json.dumps(doc)
    reparsed = json.loads(text)
    assert reparsed["@graph"]
