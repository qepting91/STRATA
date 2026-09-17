"""Adversary consensus scoring (spec section 6.4).

For each product, count distinct groups G such that
G -[:exploits]-> V -[:affects]-> product for some vuln V -- a 2-hop SQL
join over already-existing edges. This is deliberately a plain SQL join,
not a NetworkX traversal: the spec's own point (section 7.1) is that
simple joins do not need graph-library overhead, and this join is exactly
that shape.

Scope note (corpus shape, not a design compromise): the corpus's targets
edges only ever reach sector/geo, never product -- there is no
per-product targeting list in the group YAML format built in Week 2. So
"consensus" here is necessarily mediated through exploits+affects, not a
direct group-targets-product signal; that is the only signal the corpus
actually populates.

Documented no-op: spec section 6.4 says groups linked by an overlaps_with
edge should collapse into one cluster before counting, so the same actor
is not double-counted under two vendors' names. No overlaps_with edges
exist in the corpus today (Week 1-3), so that collapsing step is a
documented no-op -- every group counts as its own distinct cluster. This
is not silently ignored: if overlaps_with edges are added in a future
week, this function's group_count query should be revisited to
cluster-collapse before counting.
"""

from __future__ import annotations


def run(conn) -> list[dict]:
    """Rank products by distinct-group adversary consensus.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.

    Returns:
        A list of {"product_id": ..., "group_count": ..., "group_ids": [...]}
        dicts, sorted by group_count descending (ties broken by product_id
        for determinism).
    """
    rows = conn.execute(
        """
        SELECT affects.dst_id AS product_id, exploits.src_id AS group_id
        FROM edge AS exploits
        JOIN edge AS affects
            ON affects.src_id = exploits.dst_id
            AND affects.type = 'affects'
        WHERE exploits.type = 'exploits'
        """
    ).fetchall()

    by_product: dict[str, set[str]] = {}
    for row in rows:
        by_product.setdefault(row["product_id"], set()).add(row["group_id"])

    ranked = [
        {
            "product_id": product_id,
            "group_count": len(group_ids),
            "group_ids": sorted(group_ids),
        }
        for product_id, group_ids in by_product.items()
    ]
    ranked.sort(key=lambda r: (-r["group_count"], r["product_id"]))
    return ranked
