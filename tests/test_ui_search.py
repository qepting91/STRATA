"""Tests for the Search page's data loaders (strata.ui.data), against a
synthetic fixture DB -- not the real one, so these run everywhere."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strata.model import store


@pytest.fixture
def search_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "strata.db"
    conn = store.get_connection(db_path)
    fetched_at = "2026-01-01T00:00:00+00:00"
    store.insert_source(
        conn, id="s-1", name="test", url="https://example.test", fetched_at=fetched_at
    )

    store.insert_node(
        conn, id="sylvanite", type="group", label="SYLVANITE",
        attrs=json.dumps({"role": "initial_access_broker", "ics_kill_chain_stage": 1}),
        created_at=fetched_at,
    )
    store.insert_node(
        conn, id="tool-frp", type="tool", label="frp",
        attrs=json.dumps({"class": "tunnel"}), created_at=fetched_at,
    )
    store.insert_node(
        conn, id="CVE-2023-46805", type="vuln", label="CVE-2023-46805",
        attrs=json.dumps({"description": "Ivanti Connect Secure authentication bypass",
                          "known_ransomware_campaign_use": "Unknown"}),
        created_at=fetched_at,
    )
    store.insert_node(
        conn, id="vendor_a_product", type="product", label="Product A",
        # purdue_level is a JSON *number* in real data (enrich/purdue.py
        # writes it from config/purdue_map.yaml's numeric level values,
        # e.g. 1, 3, 3.5) -- not a string. A string here would silently
        # mask the real bug this fixture exists to catch (json_extract()
        # returns a typed int/real, which never equality-matches a bound
        # TEXT parameter under SQLite's storage-class comparison rules).
        attrs=json.dumps({"vendor": "Vendor A", "purdue_level": 3.5}),
        created_at=fetched_at,
    )
    store.insert_edge(
        conn, id="e-1", src_id="sylvanite", dst_id="tool-frp",
        type="uses", source_id="s-1",
    )
    conn.close()

    monkeypatch.setenv("STRATA_DB_PATH", str(db_path))
    import streamlit as st

    st.cache_data.clear()
    yield db_path
    st.cache_data.clear()


def test_load_node_type_counts_reflects_real_rows(search_db) -> None:
    from strata.ui.data import load_node_type_counts

    counts = load_node_type_counts()
    assert counts["group"] == 1
    assert counts["tool"] == 1
    assert counts["vuln"] == 1
    assert counts["product"] == 1


def test_search_nodes_keyword_matches_label_and_attrs(search_db) -> None:
    from strata.ui.data import search_nodes

    by_label = search_nodes(
        "frp", types=(), purdue_level=None, ics_stage=None, ransomware_only=None
    )
    assert set(by_label["id"]) == {"tool-frp"}

    by_attrs_text = search_nodes(
        "Ivanti", types=(), purdue_level=None, ics_stage=None, ransomware_only=None
    )
    assert set(by_attrs_text["id"]) == {"CVE-2023-46805"}


def test_search_nodes_type_filter_excludes_other_types(search_db) -> None:
    from strata.ui.data import search_nodes

    results = search_nodes(
        "", types=("group",), purdue_level=None, ics_stage=None, ransomware_only=None
    )
    assert set(results["type"]) == {"group"}


def test_search_nodes_dynamic_filters_apply(search_db) -> None:
    from strata.ui.data import search_nodes

    # Purdue-level filter.
    matched = search_nodes(
        "", types=("product",), purdue_level="3.5", ics_stage=None, ransomware_only=None
    )
    assert set(matched["id"]) == {"vendor_a_product"}
    unmatched = search_nodes(
        "", types=("product",), purdue_level="1", ics_stage=None, ransomware_only=None
    )
    assert unmatched.empty

    # ICS Kill Chain stage filter.
    stage_matched = search_nodes(
        "", types=("group",), purdue_level=None, ics_stage=1, ransomware_only=None
    )
    assert set(stage_matched["id"]) == {"sylvanite"}
    stage_unmatched = search_nodes(
        "", types=("group",), purdue_level=None, ics_stage=2, ransomware_only=None
    )
    assert stage_unmatched.empty


def test_search_nodes_reports_real_total_via_attrs(search_db) -> None:
    from strata.ui.data import search_nodes

    results = search_nodes(
        "", types=(), purdue_level=None, ics_stage=None, ransomware_only=None, limit=2
    )
    assert len(results) == 2
    assert results.attrs["total_matches"] == 4


def test_load_node_full_includes_real_outgoing_edge(search_db) -> None:
    from strata.ui.data import load_node_full

    detail = load_node_full("sylvanite")
    assert detail is not None
    assert detail["type"] == "group"
    assert len(detail["outgoing"]) == 1
    assert detail["outgoing"][0]["dst_id"] == "tool-frp"
    assert detail["outgoing"][0]["source_id"] == "s-1"


def test_load_node_full_missing_node_returns_none(search_db) -> None:
    from strata.ui.data import load_node_full

    assert load_node_full("does-not-exist") is None
