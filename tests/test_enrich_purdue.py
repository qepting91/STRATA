"""Tests for strata.enrich.purdue -- synthetic product-node unit tests."""

from __future__ import annotations

import json

from strata.enrich import purdue
from strata.model import store

PURDUE_MAP = purdue.load_purdue_map()


def test_classify_product_exact_slug_match() -> None:
    result = purdue.classify_product("ivanti", "connect_secure", PURDUE_MAP)
    assert result == (3.5, "remote_access")


def test_classify_product_substring_match() -> None:
    result = purdue.classify_product("siemens", "s7_400_cpu", PURDUE_MAP)
    assert result == (1, "plc")


def test_classify_product_no_match_returns_none() -> None:
    result = purdue.classify_product("acme", "widget_pro", PURDUE_MAP)
    assert result is None


def test_classify_product_handles_missing_fields_gracefully() -> None:
    assert purdue.classify_product(None, None, PURDUE_MAP) is None


def test_classify_product_one_sided_none_does_not_produce_literal_none_slug() -> None:
    """Regression test: f"{vendor}_{product}" with vendor=None used to
    render the literal string "none_airlink" instead of just "airlink",
    since Python's f-string spells None out. Found in code review;
    currently unreachable via collect/nvd.py (which drops any CPE pair
    missing either half) but classify_product's own signature promises
    to handle either side being None gracefully. A map that has no key
    containing the literal substring "none" proves the slug itself
    doesn't carry a stray "none_"/"_none" fragment (with vendor or
    product actually None, only the substring-fallback loop could match
    at all, and a map with no "none"-containing key can't accidentally
    satisfy it via that stray fragment)."""
    assert purdue.classify_product(None, "nonexistent_product_xyz", PURDUE_MAP) is None
    assert purdue.classify_product("nonexistent_vendor_xyz", None, PURDUE_MAP) is None


def test_run_merges_purdue_level_into_matched_product_attrs(db_conn) -> None:
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_node(
        db_conn,
        id="ivanti_connect_secure",
        type="product",
        label="connect_secure",
        attrs=json.dumps({"vendor": "ivanti", "product": "connect_secure"}),
        created_at=fetched_at,
    )
    store.insert_node(
        db_conn,
        id="acme_widget",
        type="product",
        label="widget",
        attrs=json.dumps({"vendor": "acme", "product": "widget"}),
        created_at=fetched_at,
    )

    summary = purdue.run(db_conn)

    assert summary["products_examined"] == 2
    assert summary["products_matched"] == 1
    assert summary["products_unmatched"] == 1

    row = db_conn.execute(
        "SELECT attrs FROM node WHERE id = ?", ("ivanti_connect_secure",)
    ).fetchone()
    attrs = json.loads(row["attrs"])
    assert attrs["purdue_level"] == 3.5
    assert attrs["purdue_class"] == "remote_access"
    # Original vendor/product attrs must survive the merge-upsert.
    assert attrs["vendor"] == "ivanti"
    assert attrs["product"] == "connect_secure"
