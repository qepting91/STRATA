"""Tests for strata.hunt.methods's 5 python-hunt functions against fixture DBs."""

from __future__ import annotations

import json

from strata.hunt import methods
from strata.model import store

_FETCHED = "2026-01-01T00:00:00Z"


def _src(conn, sid="s-1") -> None:
    store.insert_source(conn, id=sid, name="test", url=None, fetched_at=_FETCHED)


def test_h002_no_data_returns_zero(db_conn) -> None:
    _src(db_conn)
    result = methods.h002_poc_to_group_use(db_conn)
    assert result == {"n": 0, "groups_with_n_gte_3": 0, "median_days": None}


def test_h002_computes_median_when_present(db_conn) -> None:
    _src(db_conn)
    store.insert_node(
        db_conn, id="CVE-1", type="vuln", label="CVE-1", attrs=None, created_at=_FETCHED
    )
    store.insert_metric_observation(
        db_conn, id="m1", node_id="CVE-1", metric_name="disclosure_to_group_use",
        value=5.0, model_version=None, observed_at=_FETCHED, source_id="s-1",
    )
    result = methods.h002_poc_to_group_use(db_conn)
    assert result["n"] == 1
    assert result["median_days"] == 5.0


def test_h004_zero_shared_tools(db_conn) -> None:
    _src(db_conn)
    for gid in ("group-a", "group-b"):
        store.insert_node(db_conn, id=gid, type="group", label=gid, attrs=None, created_at=_FETCHED)
    for tid in ("tool-1", "tool-2"):
        store.insert_node(db_conn, id=tid, type="tool", label=tid, attrs=None, created_at=_FETCHED)
    store.insert_edge(
        db_conn, id="u1", src_id="group-a", dst_id="tool-1", type="uses", source_id="s-1"
    )
    store.insert_edge(
        db_conn, id="u2", src_id="group-b", dst_id="tool-2", type="uses", source_id="s-1"
    )
    result = methods.h004_webshell_distinctiveness(db_conn)
    assert result["n_tools_compared"] == 2
    assert result["n_tools_shared_across_groups"] == 0


def test_h004_detects_shared_tool(db_conn) -> None:
    _src(db_conn)
    for gid in ("group-a", "group-b"):
        store.insert_node(db_conn, id=gid, type="group", label=gid, attrs=None, created_at=_FETCHED)
    store.insert_node(
        db_conn, id="tool-shared", type="tool", label="tool-shared",
        attrs=None, created_at=_FETCHED,
    )
    store.insert_edge(
        db_conn, id="u1", src_id="group-a", dst_id="tool-shared", type="uses", source_id="s-1"
    )
    store.insert_edge(
        db_conn, id="u2", src_id="group-b", dst_id="tool-shared", type="uses", source_id="s-1"
    )
    result = methods.h004_webshell_distinctiveness(db_conn)
    assert result["n_tools_shared_across_groups"] == 1


def test_h005_zero_overlap(db_conn) -> None:
    _src(db_conn)
    store.insert_node(
        db_conn, id="CVE-1", type="vuln", label="CVE-1",
        attrs=json.dumps({"known_ransomware_campaign_use": "Known"}),
        created_at=_FETCHED,
    )
    store.insert_node(
        db_conn, id="CVE-2", type="vuln", label="CVE-2",
        attrs=json.dumps({"known_ransomware_campaign_use": "Unknown"}),
        created_at=_FETCHED,
    )
    result = methods.h005_ransomware_protocol_overlap(db_conn)
    assert result["n_ransomware_cves"] == 1
    assert result["n_ransomware_cves_with_protocol_involvement"] == 0
    assert result["overlap_rate"] == 0.0


def test_h005_detects_overlap(db_conn) -> None:
    _src(db_conn)
    store.insert_node(
        db_conn, id="CVE-1", type="vuln", label="CVE-1",
        attrs=json.dumps({"known_ransomware_campaign_use": "Known"}),
        created_at=_FETCHED,
    )
    store.insert_node(
        db_conn, id="protocol-modbus", type="protocol", label="Modbus",
        attrs=None, created_at=_FETCHED,
    )
    store.insert_edge(
        db_conn, id="e1", src_id="CVE-1", dst_id="protocol-modbus",
        type="involves", source_id="s-1",
    )
    result = methods.h005_ransomware_protocol_overlap(db_conn)
    assert result["n_ransomware_cves_with_protocol_involvement"] == 1
    assert result["overlap_rate"] == 1.0


def test_h006_no_qualifying_products(db_conn) -> None:
    _src(db_conn)
    store.insert_node(
        db_conn, id="group-a", type="group", label="a", attrs=None, created_at=_FETCHED
    )
    store.insert_node(
        db_conn, id="CVE-1", type="vuln", label="CVE-1", attrs=None, created_at=_FETCHED
    )
    store.insert_node(
        db_conn, id="product-x", type="product", label="x",
        attrs=json.dumps({"purdue_class": "plc"}), created_at=_FETCHED,
    )
    store.insert_edge(
        db_conn, id="e1", src_id="group-a", dst_id="CVE-1", type="exploits", source_id="s-1"
    )
    store.insert_edge(
        db_conn, id="e2", src_id="CVE-1", dst_id="product-x", type="affects", source_id="s-1"
    )
    result = methods.h006_cellular_gateway_convergence(db_conn)
    assert result["n"] == 0


def test_h006_finds_qualifying_cellular_gateway(db_conn) -> None:
    _src(db_conn)
    for gid in ("group-a", "group-b"):
        store.insert_node(db_conn, id=gid, type="group", label=gid, attrs=None, created_at=_FETCHED)
    for cid in ("CVE-1", "CVE-2"):
        store.insert_node(db_conn, id=cid, type="vuln", label=cid, attrs=None, created_at=_FETCHED)
    store.insert_node(
        db_conn, id="product-gw", type="product", label="gw",
        attrs=json.dumps({"purdue_class": "cellular_gateway"}), created_at=_FETCHED,
    )
    store.insert_edge(
        db_conn, id="e1", src_id="group-a", dst_id="CVE-1", type="exploits", source_id="s-1"
    )
    store.insert_edge(
        db_conn, id="e2", src_id="group-b", dst_id="CVE-2", type="exploits", source_id="s-1"
    )
    store.insert_edge(
        db_conn, id="e3", src_id="CVE-1", dst_id="product-gw", type="affects", source_id="s-1"
    )
    store.insert_edge(
        db_conn, id="e4", src_id="CVE-2", dst_id="product-gw", type="affects", source_id="s-1"
    )
    result = methods.h006_cellular_gateway_convergence(db_conn)
    assert result["n"] == 1
    assert result["qualifying_products"] == ["product-gw"]


def test_h008_small_protocol_sample(db_conn) -> None:
    _src(db_conn)
    store.insert_node(
        db_conn, id="CVE-1", type="vuln", label="CVE-1",
        attrs=json.dumps({"nvd_published": "2020-01-01T00:00:00"}),
        created_at=_FETCHED,
    )
    store.insert_node(
        db_conn, id="protocol-modbus", type="protocol", label="Modbus",
        attrs=None, created_at=_FETCHED,
    )
    store.insert_edge(
        db_conn, id="e1", src_id="CVE-1", dst_id="protocol-modbus",
        type="involves", source_id="s-1",
    )
    result = methods.h008_protocol_vs_edge_cve_trend(db_conn)
    assert result["n_protocol_cves"] == 1
    assert result["protocol_cves_by_year"] == {2020: 1}
