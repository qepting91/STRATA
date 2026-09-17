"""Tests for strata.collect.nvd, mocked via respx against a trimmed fixture."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.nvd import NVD_URL, NVDCollector
from strata.model import store


def _make_net_client(tmp_path: Path) -> net.NetClient:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("services.nvd.nist.gov\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."services.nvd.nist.gov"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    return net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )


@respx.mock
def test_nvd_enriches_existing_vuln_node_preserving_old_attrs(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    fixture = json.loads(
        (fixtures_dir / "nvd_cve_2023_46805.json").read_text(encoding="utf-8")
    )
    respx.get(f"{NVD_URL}?cveId=CVE-2023-46805").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    # Seed a pre-existing vuln node, as KEV would have created, with a field
    # that NVD's payload does not carry -- this must survive the merge.
    store.insert_node(
        conn,
        id="CVE-2023-46805",
        type="vuln",
        label="CVE-2023-46805",
        attrs=json.dumps({"vendor_project": "Ivanti", "date_added": "2024-01-10"}),
        created_at="2026-01-01T00:00:00Z",
    )

    collector = NVDCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "nvd"
    assert summary["sources"] == 1

    row = conn.execute(
        "SELECT attrs FROM node WHERE id = ?", ("CVE-2023-46805",)
    ).fetchone()
    attrs = json.loads(row["attrs"])
    # Old KEV-era fields survive the merge-upsert...
    assert attrs["vendor_project"] == "Ivanti"
    assert attrs["date_added"] == "2024-01-10"
    # ...and new NVD fields land.
    assert attrs["cvss_v31_base"] == 8.2
    assert attrs["cwe"] == ["CWE-287"]
    # ...including the English description text (first `en` entry), which
    # the enrich.protocol classifier depends on -- must not pick up the
    # non-English entry.
    assert attrs["description"] == (
        "An authentication bypass vulnerability in the web component of "
        "Ivanti Connect Secure allows a remote attacker to access "
        "restricted resources by bypassing control checks."
    )

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("product") == 2  # connect_secure, policy_secure
    assert node_counts.get("vendor") == 1  # ivanti

    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("made_by") == 2
    assert edge_counts.get("affects") == 2

    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM edge e JOIN source s ON s.id = e.source_id"
    ).fetchone()
    assert joined["n"] == edge_counts["made_by"] + edge_counts["affects"]

    net_client.close()
    conn.close()


@respx.mock
def test_nvd_since_is_ignored_not_erroring(tmp_path: Path, fixtures_dir: Path) -> None:
    fixture = json.loads(
        (fixtures_dir / "nvd_cve_2023_46805.json").read_text(encoding="utf-8")
    )
    respx.get(f"{NVD_URL}?cveId=CVE-2023-46805").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")
    store.insert_node(
        conn,
        id="CVE-2023-46805",
        type="vuln",
        label="CVE-2023-46805",
        attrs=None,
        created_at="2026-01-01T00:00:00Z",
    )

    import datetime as dt

    collector = NVDCollector(net_client)
    collector.since = dt.date(2030, 1, 1)
    summary = collector.run(conn, offline=False)

    # Not an error, and the one known CVE is still enriched despite --since.
    assert summary["sources"] == 1

    net_client.close()
    conn.close()
