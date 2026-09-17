"""Purdue Enterprise Reference Architecture level assignment (spec section 6.3).

Hand-curated mapping in config/purdue_map.yaml, joined via a product node's
vendor/product attrs (set by collect/nvd.py's CPE join). classify_product()
is a pure matching function; run() reads every product node via
store.get_all_products() and merge-upserts purdue_level/purdue_class into
each matched product's attrs via the existing merge-upsert insert_node().

No new source_id is needed for this enrichment pass: it is a static
classification against a hand-curated local config file, not an externally
fetched claim being newly asserted. The existing merge-upsert design
already treats attrs-only enrichment as a denormalization convenience, not
part of the provenance record (see store.insert_node's docstring) -- edges
and metric_observation rows are what carry source_id, and this pass writes
neither.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import yaml

from strata.model import store


def load_purdue_map(path: Path | str = "config/purdue_map.yaml") -> dict:
    """Load config/purdue_map.yaml.

    Args:
        path: Path to the purdue_map YAML file.

    Returns:
        The parsed YAML dict with "levels" and "products" top-level keys.
    """
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return data


def classify_product(
    vendor: str | None, product: str | None, purdue_map: dict
) -> tuple[float, str] | None:
    """Match a product's vendor/product attrs against config/purdue_map.yaml.

    Pure function: no I/O, no database access. Tries, in order: an exact
    match on the {vendor}_{product} slug against the products table keys,
    then a substring match (either direction) against each key -- to
    tolerate minor CPE-vendor/product-name spelling differences without
    inventing a fuzzy-matching dependency this week.

    Args:
        vendor: The product node's vendor attr.
        product: The product node's product attr.
        purdue_map: The dict returned by load_purdue_map().

    Returns:
        (level, class) if a confident match is found, else None -- callers
        must handle "no mapping found" gracefully, not error.
    """
    products = purdue_map.get("products") or {}
    if not vendor and not product:
        return None

    # `vendor or ""`/`product or ""`, not f"{vendor}_{product}" directly --
    # the latter renders a None side as the literal string "none", giving
    # a bogus slug like "none_airlink" that can never legitimately match
    # (found in review: currently unreachable since collect/nvd.py's CPE
    # parser drops any pair missing either half, but classify_product's
    # own signature accepts vendor/product independently as `str | None`,
    # so this is a real latent bug in the function's own contract).
    slug = f"{vendor or ''}_{product or ''}".strip("_").lower() if (vendor or product) else ""

    if slug in products:
        entry = products[slug]
        return entry["level"], entry["class"]

    for key, entry in products.items():
        key_lower = key.lower()
        if slug and (slug in key_lower or key_lower in slug):
            return entry["level"], entry["class"]

    return None


def run(conn, purdue_map_path: Path | str = "config/purdue_map.yaml") -> dict:
    """Classify every product node's Purdue level/class and merge into attrs.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.
        purdue_map_path: Path to config/purdue_map.yaml.

    Returns:
        Summary dict: products examined, products matched, products
        unmatched.
    """
    purdue_map = load_purdue_map(purdue_map_path)
    fetched_at = datetime.now(UTC).isoformat()

    products = store.get_all_products(conn)
    matched = 0
    unmatched = 0

    for prod in products:
        attrs = prod.get("attrs") or {}
        vendor = attrs.get("vendor")
        product_name = attrs.get("product")
        result = classify_product(vendor, product_name, purdue_map)
        if result is None:
            unmatched += 1
            continue

        level, product_class = result
        matched += 1
        store.insert_node(
            conn,
            id=prod["id"],
            type="product",
            label=prod["label"],
            attrs=json.dumps({"purdue_level": level, "purdue_class": product_class}),
            created_at=fetched_at,
        )

    return {
        "products_examined": len(products),
        "products_matched": matched,
        "products_unmatched": unmatched,
    }
