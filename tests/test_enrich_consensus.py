"""Tests for strata.enrich.consensus against a small fixture DB."""

from __future__ import annotations

from strata.enrich import consensus
from strata.model import store


def _seed(conn) -> None:
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_source(conn, id="s-1", name="corpus", url=None, fetched_at=fetched_at)

    for gid in ("group-a", "group-b", "group-c"):
        store.insert_node(conn, id=gid, type="group", label=gid, attrs=None, created_at=fetched_at)
    for cve in ("CVE-1", "CVE-2", "CVE-3"):
        store.insert_node(conn, id=cve, type="vuln", label=cve, attrs=None, created_at=fetched_at)
    for pid in ("product-x", "product-y"):
        store.insert_node(
            conn, id=pid, type="product", label=pid, attrs=None, created_at=fetched_at
        )

    # product-x is affected by CVE-1 and CVE-2; product-y only by CVE-3.
    store.insert_edge(
        conn, id="e-affects-1", src_id="CVE-1", dst_id="product-x",
        type="affects", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e-affects-2", src_id="CVE-2", dst_id="product-x",
        type="affects", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e-affects-3", src_id="CVE-3", dst_id="product-y",
        type="affects", source_id="s-1",
    )

    # group-a exploits CVE-1, group-b exploits CVE-2 (both -> product-x:
    # 2 distinct groups). group-c also exploits CVE-1 (product-x: 3rd
    # group). group-a additionally exploits CVE-3 (product-y: 1 group).
    store.insert_edge(
        conn, id="e-exploits-1", src_id="group-a", dst_id="CVE-1",
        type="exploits", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e-exploits-2", src_id="group-b", dst_id="CVE-2",
        type="exploits", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e-exploits-3", src_id="group-c", dst_id="CVE-1",
        type="exploits", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e-exploits-4", src_id="group-a", dst_id="CVE-3",
        type="exploits", source_id="s-1",
    )


def test_consensus_ranks_products_by_distinct_group_count(db_conn) -> None:
    _seed(db_conn)
    ranked = consensus.run(db_conn)

    by_id = {r["product_id"]: r for r in ranked}
    assert by_id["product-x"]["group_count"] == 3
    assert set(by_id["product-x"]["group_ids"]) == {"group-a", "group-b", "group-c"}
    assert by_id["product-y"]["group_count"] == 1
    assert by_id["product-y"]["group_ids"] == ["group-a"]

    # Sorted descending by group_count.
    assert ranked[0]["product_id"] == "product-x"
    assert ranked[1]["product_id"] == "product-y"


def test_consensus_returns_empty_list_for_empty_graph(db_conn) -> None:
    assert consensus.run(db_conn) == []
