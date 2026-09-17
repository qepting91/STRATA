"""Tests for strata.hunt.methods's python-hunt functions against fixture DBs."""

from __future__ import annotations

import json
from datetime import date, timedelta

from strata.hunt import methods
from strata.hunt.runner import load_hunt, run_hunt
from strata.hunt.verdicts import evaluate_verdict
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


def _insert_vendor_advisory(
    conn, *, vendor: str, advisory_id: str, initial_release_date: str, cve: str, cve_attrs: dict
) -> None:
    source_id = f"{vendor}-{advisory_id}"
    store.insert_source(conn, id=source_id, name=vendor, url=None, fetched_at=_FETCHED)
    store.insert_node(
        conn, id=advisory_id, type="advisory", label=advisory_id,
        attrs=json.dumps({"initial_release_date": initial_release_date, "vendor": vendor}),
        created_at=_FETCHED,
    )
    store.insert_node(
        conn, id=cve, type="vuln", label=cve, attrs=json.dumps(cve_attrs), created_at=_FETCHED
    )
    store.insert_edge(
        conn, id=f"{advisory_id}--describes--{cve}", src_id=advisory_id, dst_id=cve,
        type="describes", source_id=source_id,
    )


def test_h010_insufficient_with_only_one_vendor(db_conn) -> None:
    _insert_vendor_advisory(
        db_conn, vendor="siemens-psirt", advisory_id="SSA-1",
        initial_release_date="2026-02-01", cve="CVE-2026-0001",
        cve_attrs={"nvd_published": "2026-01-01T00:00:00"},
    )
    result = methods.h010_vendor_patch_latency(db_conn)
    assert result["n_vendors_with_data"] == 1
    assert result["median_latency_diff_days"] is None


def _insert_n_advisories(conn, *, vendor: str, prefix: str, days_latency: list[int]) -> None:
    """Insert one advisory+CVE pair per entry in days_latency, each with
    that exact (advisory_date - cve_date) gap, all anchored to a fixed
    CVE disclosure date so the resulting per-vendor median is exact and
    easy to assert on."""
    for i, latency in enumerate(days_latency):
        cve_date = date(2026, 1, 1)
        advisory_date = cve_date + timedelta(days=latency)
        _insert_vendor_advisory(
            conn, vendor=vendor, advisory_id=f"{prefix}-{i}",
            initial_release_date=advisory_date.isoformat(), cve=f"CVE-2026-{prefix}{i:04d}",
            cve_attrs={"nvd_published": cve_date.isoformat() + "T00:00:00"},
        )


def test_h010_computes_latency_for_two_vendors(db_conn) -> None:
    _insert_n_advisories(db_conn, vendor="siemens-psirt", prefix="SSA", days_latency=[30, 31, 32])
    _insert_n_advisories(
        db_conn, vendor="schneider-psirt", prefix="SEVD", days_latency=[89, 90, 91]
    )
    result = methods.h010_vendor_patch_latency(db_conn)
    assert result["n_vendors_with_data"] == 2
    assert result["min_n_per_vendor"] == 3
    assert result["siemens_psirt_median_days"] == 31
    assert result["schneider_psirt_median_days"] == 90
    assert result["median_latency_diff_days"] == 59


def test_h010_hunt_yaml_end_to_end_with_two_vendors(db_conn) -> None:
    """H010's real hunts/*.yaml wiring, not just the bare method function.

    Each vendor needs >=3 latency points (min_n_per_vendor gate) for a
    trustworthy SUPPORTED/REFUTED verdict -- a median over 1-2 points is
    a single anecdote, not a vendor latency figure (found live: the real
    Schneider collection this session had only 1 computable point)."""
    _insert_n_advisories(db_conn, vendor="siemens-psirt", prefix="SSA", days_latency=[30, 31, 32])
    _insert_n_advisories(
        db_conn, vendor="schneider-psirt", prefix="SEVD", days_latency=[89, 90, 91]
    )
    hunt = load_hunt("hunts/H010-vendor-patch-latency.yaml")
    result = run_hunt(db_conn, hunt)
    verdict = evaluate_verdict(result.namespace, hunt.insufficient_if, hunt.falsifies_if)
    assert result.namespace["n_vendors_with_data"] == 2
    assert result.namespace["min_n_per_vendor"] == 3
    # 59-day median diff (>= 30) does not refute the >30-day hypothesis.
    assert verdict == "SUPPORTED"


def test_h010_hunt_yaml_insufficient_with_one_vendor(db_conn) -> None:
    _insert_vendor_advisory(
        db_conn, vendor="siemens-psirt", advisory_id="SSA-1",
        initial_release_date="2026-02-01", cve="CVE-2026-0001",
        cve_attrs={"nvd_published": "2026-01-01T00:00:00"},
    )
    hunt = load_hunt("hunts/H010-vendor-patch-latency.yaml")
    result = run_hunt(db_conn, hunt)
    verdict = evaluate_verdict(result.namespace, hunt.insufficient_if, hunt.falsifies_if)
    assert verdict == "INSUFFICIENT"


def test_h010_hunt_yaml_insufficient_when_one_vendor_sample_too_thin(db_conn) -> None:
    """Regression test: both vendors present (n_vendors_with_data == 2)
    but one has only 1 data point -- this used to report SUPPORTED on a
    single Schneider anecdote before the min_n_per_vendor >= 3 floor was
    added (found live in this session's real collection run)."""
    _insert_n_advisories(db_conn, vendor="siemens-psirt", prefix="SSA", days_latency=[30, 31, 32])
    _insert_n_advisories(db_conn, vendor="schneider-psirt", prefix="SEVD", days_latency=[90])
    hunt = load_hunt("hunts/H010-vendor-patch-latency.yaml")
    result = run_hunt(db_conn, hunt)
    verdict = evaluate_verdict(result.namespace, hunt.insufficient_if, hunt.falsifies_if)
    assert result.namespace["n_vendors_with_data"] == 2
    assert result.namespace["min_n_per_vendor"] == 1
    assert verdict == "INSUFFICIENT"


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
