"""Tests for the SQLite DAO in strata.model.store.

The provenance-constraint tests are the literal spec requirement: an edge
insert with a null or non-existent source_id MUST raise
sqlite3.IntegrityError. This is the single most important invariant in the
Week 1 build.
"""

from __future__ import annotations

import sqlite3

import pytest

from strata.model import store


def test_insert_source_node_edge_succeed(db_conn: sqlite3.Connection) -> None:
    store.insert_source(
        db_conn,
        id="src-1",
        name="test-source",
        url="https://example.test/feed",
        fetched_at="2026-01-01T00:00:00Z",
        sha256="abc123",
        http_status=200,
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-0001",
        type="vuln",
        label="CVE-2024-0001",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="advisory-1",
        type="advisory",
        label="Advisory 1",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )

    # Should not raise.
    store.insert_edge(
        db_conn,
        id="edge-1",
        src_id="advisory-1",
        dst_id="CVE-2024-0001",
        type="describes",
        source_id="src-1",
    )

    counts = store.count_edges_by_type(db_conn)
    assert counts == {"describes": 1}
    assert store.count_sources(db_conn) == 1
    node_counts = store.count_nodes_by_type(db_conn)
    assert node_counts["vuln"] == 1
    assert node_counts["advisory"] == 1


def test_insert_edge_with_null_source_id_raises(
    db_conn: sqlite3.Connection,
) -> None:
    store.insert_node(
        db_conn,
        id="node-a",
        type="vuln",
        label="A",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="node-b",
        type="advisory",
        label="B",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )

    with pytest.raises(sqlite3.IntegrityError):
        store.insert_edge(
            db_conn,
            id="edge-null-src",
            src_id="node-b",
            dst_id="node-a",
            type="describes",
            source_id=None,
        )


def test_insert_edge_with_nonexistent_source_id_raises(
    db_conn: sqlite3.Connection,
) -> None:
    store.insert_node(
        db_conn,
        id="node-a2",
        type="vuln",
        label="A2",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="node-b2",
        type="advisory",
        label="B2",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )

    with pytest.raises(sqlite3.IntegrityError):
        store.insert_edge(
            db_conn,
            id="edge-bad-src",
            src_id="node-b2",
            dst_id="node-a2",
            type="describes",
            source_id="does-not-exist",
        )


def test_node_upsert_is_idempotent(db_conn: sqlite3.Connection) -> None:
    store.insert_node(
        db_conn,
        id="dup-node",
        type="vuln",
        label="first label",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="dup-node",
        type="vuln",
        label="second label",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    row = db_conn.execute(
        "SELECT label FROM node WHERE id = ?", ("dup-node",)
    ).fetchone()
    assert row["label"] == "second label"
    assert store.count_nodes_by_type(db_conn)["vuln"] == 1
