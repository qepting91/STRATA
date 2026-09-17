"""The 5 python-method hunts custom logic (H002, H004, H005, H006, H008)."""

from __future__ import annotations

import json
import statistics


def h002_poc_to_group_use(conn) -> dict:
    """H002: disclosure-to-group-use interval, median/n by group."""
    rows = conn.execute(
        "SELECT node_id, value FROM metric_observation "
        "WHERE metric_name = 'disclosure_to_group_use'"
    ).fetchall()

    by_group: dict[str, list[float]] = {}
    for row in rows:
        by_group.setdefault(row["node_id"], []).append(row["value"])

    groups_with_n_gte_3 = sum(1 for values in by_group.values() if len(values) >= 3)
    median_days = None
    all_values = [v for values in by_group.values() for v in values]
    if all_values:
        median_days = statistics.median(all_values)

    return {
        "n": len(rows),
        "groups_with_n_gte_3": groups_with_n_gte_3,
        "median_days": median_days,
    }


def h004_webshell_distinctiveness(conn) -> dict:
    """H004: is tool/webshell choice group-distinctive?"""
    rows = conn.execute(
        """
        SELECT dst_id AS tool_id, src_id AS group_id
        FROM edge
        WHERE type = 'uses'
        """
    ).fetchall()

    by_tool: dict[str, set[str]] = {}
    for row in rows:
        by_tool.setdefault(row["tool_id"], set()).add(row["group_id"])

    n_tools_compared = len(by_tool)
    n_tools_shared_across_groups = sum(
        1 for groups in by_tool.values() if len(groups) >= 2
    )

    return {
        "n_tools_compared": n_tools_compared,
        "n_tools_shared_across_groups": n_tools_shared_across_groups,
        "n_uses_edges": len(rows),
    }


def h005_ransomware_protocol_overlap(conn) -> dict:
    """H005: ransomware-affecting CVEs show no ICS-native protocol involvement."""
    vuln_rows = conn.execute("SELECT id, attrs FROM node WHERE type = 'vuln'").fetchall()

    ransomware_cves: list[str] = []
    for row in vuln_rows:
        if not row["attrs"]:
            continue
        try:
            attrs = json.loads(row["attrs"])
        except json.JSONDecodeError:
            continue
        if attrs.get("known_ransomware_campaign_use") == "Known":
            ransomware_cves.append(row["id"])

    n_ransomware_cves = len(ransomware_cves)
    n_with_involvement = 0
    if ransomware_cves:
        placeholders = ",".join("?" for _ in ransomware_cves)
        involved_rows = conn.execute(
            f"SELECT DISTINCT src_id FROM edge "
            f"WHERE type = 'involves' AND src_id IN ({placeholders})",
            ransomware_cves,
        ).fetchall()
        n_with_involvement = len(involved_rows)

    overlap_rate = (
        n_with_involvement / n_ransomware_cves if n_ransomware_cves else 0.0
    )

    return {
        "n_ransomware_cves": n_ransomware_cves,
        "n_ransomware_cves_with_protocol_involvement": n_with_involvement,
        "overlap_rate": overlap_rate,
    }


def h006_cellular_gateway_convergence(conn) -> dict:
    """H006: cellular-gateway product families targeted by >=2 unrelated groups."""
    rows = conn.execute(
        """
        SELECT affects.dst_id AS product_id, exploits.src_id AS group_id, p.attrs AS attrs
        FROM edge AS exploits
        JOIN edge AS affects
            ON affects.src_id = exploits.dst_id AND affects.type = 'affects'
        JOIN node AS p
            ON p.id = affects.dst_id AND p.type = 'product'
        WHERE exploits.type = 'exploits'
        """
    ).fetchall()

    by_product: dict[str, set[str]] = {}
    for row in rows:
        if not row["attrs"]:
            continue
        try:
            attrs = json.loads(row["attrs"])
        except json.JSONDecodeError:
            continue
        if attrs.get("purdue_class") != "cellular_gateway":
            continue
        by_product.setdefault(row["product_id"], set()).add(row["group_id"])

    qualifying = {pid: groups for pid, groups in by_product.items() if len(groups) >= 2}

    return {
        "n": len(qualifying),
        "n_cellular_gateway_products_examined": len(by_product),
        "qualifying_products": sorted(qualifying),
    }


def h008_protocol_vs_edge_cve_trend(conn) -> dict:
    """H008: protocol-native CVE volume flat vs. edge (Purdue 3.5) CVE volume growing."""
    vuln_rows = conn.execute("SELECT id, attrs FROM node WHERE type = 'vuln'").fetchall()
    year_by_cve: dict[str, int | None] = {}
    for row in vuln_rows:
        year = None
        if row["attrs"]:
            try:
                attrs = json.loads(row["attrs"])
                published = attrs.get("nvd_published")
                if published:
                    year = int(str(published)[:4])
            except (json.JSONDecodeError, ValueError):
                year = None
        year_by_cve[row["id"]] = year

    protocol_cves = {
        row["src_id"]
        for row in conn.execute(
            "SELECT DISTINCT src_id FROM edge WHERE type = 'involves'"
        ).fetchall()
    }

    edge_product_rows = conn.execute(
        """
        SELECT DISTINCT affects.src_id AS cve_id
        FROM edge AS affects
        JOIN node AS p ON p.id = affects.dst_id AND p.type = 'product'
        WHERE affects.type = 'affects'
        """
    ).fetchall()
    edge_cves: set[str] = set()
    for row in edge_product_rows:
        edge_cves.add(row["cve_id"])

    purdue_35_products: set[str] = set()
    for prow in conn.execute("SELECT id, attrs FROM node WHERE type = 'product'").fetchall():
        if not prow["attrs"]:
            continue
        try:
            pattrs = json.loads(prow["attrs"])
        except json.JSONDecodeError:
            continue
        if pattrs.get("purdue_level") == 3.5:
            purdue_35_products.add(prow["id"])

    edge_cves_35: set[str] = set()
    for row in conn.execute(
        "SELECT src_id, dst_id FROM edge WHERE type = 'affects'"
    ).fetchall():
        if row["dst_id"] in purdue_35_products:
            edge_cves_35.add(row["src_id"])

    protocol_by_year: dict[int, int] = {}
    for cve in protocol_cves:
        year = year_by_cve.get(cve)
        if year is not None:
            protocol_by_year[year] = protocol_by_year.get(year, 0) + 1

    edge_by_year: dict[int, int] = {}
    for cve in edge_cves_35:
        year = year_by_cve.get(cve)
        if year is not None:
            edge_by_year[year] = edge_by_year.get(year, 0) + 1

    return {
        "n_protocol_cves": len(protocol_cves),
        "n_edge_cves": len(edge_cves_35),
        "protocol_cves_by_year": protocol_by_year,
        "edge_cves_by_year": edge_by_year,
    }


METHODS = {
    "h002_poc_to_group_use": h002_poc_to_group_use,
    "h004_webshell_distinctiveness": h004_webshell_distinctiveness,
    "h005_ransomware_protocol_overlap": h005_ransomware_protocol_overlap,
    "h006_cellular_gateway_convergence": h006_cellular_gateway_convergence,
    "h008_protocol_vs_edge_cve_trend": h008_protocol_vs_edge_cve_trend,
}
