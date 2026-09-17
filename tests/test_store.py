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


def test_node_attrs_merge_upsert_preserves_old_fields(
    db_conn: sqlite3.Connection,
) -> None:
    """Regression test: a second insert with different new fields must not
    clobber fields written by an earlier insert (e.g. KEV writing
    vendor_project, then NVD later adding cvss_v31 to the same CVE node)."""
    import json

    store.insert_node(
        db_conn,
        id="CVE-2024-9999",
        type="vuln",
        label="CVE-2024-9999",
        attrs=json.dumps({"vendor_project": "Acme", "date_added": "2024-01-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-9999",
        type="vuln",
        label="CVE-2024-9999",
        attrs=json.dumps({"cvss_v31_base": 8.2, "cwe": ["CWE-287"]}),
        created_at="2026-01-01T00:00:00Z",
    )

    row = db_conn.execute(
        "SELECT attrs FROM node WHERE id = ?", ("CVE-2024-9999",)
    ).fetchone()
    merged = json.loads(row["attrs"])

    # Old fields survive...
    assert merged["vendor_project"] == "Acme"
    assert merged["date_added"] == "2024-01-01"
    # ...and new fields land.
    assert merged["cvss_v31_base"] == 8.2
    assert merged["cwe"] == ["CWE-287"]


def test_node_attrs_merge_upsert_new_key_wins_on_overlap(
    db_conn: sqlite3.Connection,
) -> None:
    import json

    store.insert_node(
        db_conn,
        id="CVE-2024-8888",
        type="vuln",
        label="CVE-2024-8888",
        attrs=json.dumps({"cvss_v31_base": 5.0}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-8888",
        type="vuln",
        label="CVE-2024-8888",
        attrs=json.dumps({"cvss_v31_base": 9.8}),
        created_at="2026-01-01T00:00:00Z",
    )
    row = db_conn.execute(
        "SELECT attrs FROM node WHERE id = ?", ("CVE-2024-8888",)
    ).fetchone()
    assert json.loads(row["attrs"])["cvss_v31_base"] == 9.8


def test_get_all_vuln_cve_ids(db_conn: sqlite3.Connection) -> None:
    store.insert_node(
        db_conn,
        id="CVE-2024-1111",
        type="vuln",
        label="CVE-2024-1111",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="advisory-x",
        type="advisory",
        label="X",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    assert store.get_all_vuln_cve_ids(db_conn) == {"CVE-2024-1111"}


def test_insert_signal_and_count_by_source(db_conn: sqlite3.Connection) -> None:
    store.insert_source(
        db_conn,
        id="src-signal",
        name="poc-github",
        url="https://example.test",
        fetched_at="2026-01-01T00:00:00Z",
    )
    store.insert_signal(
        db_conn,
        id="sig-1",
        cve="CVE-2024-1111",
        source="poc-github",
        signal_type="poc_repo_created",
        ref="https://github.com/foo/bar",
        observed_at="2024-02-01T00:00:00Z",
        meta=None,
        source_id="src-signal",
    )
    assert store.count_signals_by_source(db_conn) == {"poc-github": 1}


def test_insert_signal_with_invalid_source_id_raises(
    db_conn: sqlite3.Connection,
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_signal(
            db_conn,
            id="sig-bad",
            cve="CVE-2024-1111",
            source="poc-github",
            signal_type="poc_repo_created",
            ref=None,
            observed_at="2024-02-01T00:00:00Z",
            meta=None,
            source_id="does-not-exist",
        )


def test_insert_metric_observation_and_count(db_conn: sqlite3.Connection) -> None:
    store.insert_source(
        db_conn,
        id="src-epss",
        name="epss",
        url="https://api.first.org/data/v1/epss",
        fetched_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-1111",
        type="vuln",
        label="CVE-2024-1111",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_metric_observation(
        db_conn,
        id="CVE-2024-1111-epss-2026-01-01",
        node_id="CVE-2024-1111",
        metric_name="epss",
        value=0.42,
        model_version=None,
        observed_at="2026-01-01",
        source_id="src-epss",
    )
    assert store.count_metric_observations_by_name(db_conn) == {"epss": 1}
