"""Tests for strata.collect.cisa_csaf, mocked via respx against fixtures."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.cisa_csaf import RAW_BASE, TREE_URL, CISACSAFCollector
from strata.model import store


def _make_net_client(tmp_path: Path) -> net.NetClient:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text(
        "api.github.com\nraw.githubusercontent.com\n", encoding="utf-8"
    )
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."api.github.com"]\nmax_requests = 1000\nwindow_seconds = 1.0\n'
        '[hosts."raw.githubusercontent.com"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    return net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )


@respx.mock
def test_csaf_collect_lands_advisories_vulns_and_describes_edges(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    tree_fixture = json.loads(
        (fixtures_dir / "csaf_tree_sample.json").read_text(encoding="utf-8")
    )
    respx.get(TREE_URL).mock(return_value=httpx.Response(200, json=tree_fixture))

    base_advisory = json.loads(
        (fixtures_dir / "csaf_advisory_sample.json").read_text(encoding="utf-8")
    )

    # The fixture tree, filtered to the current year, yields 4 candidate
    # paths (see csaf_tree_sample.json). Serve a distinct advisory doc
    # (distinct tracking id + CVE) for each so the test can verify
    # per-file provenance, not just repeated identical content.
    expected_paths = [
        "csaf_files/OT/white/2026/icsa-26-015-02.json",
        "csaf_files/OT/white/2026/icsa-26-013-01.json",
        "csaf_files/IT/white/2026/va-26-008-01.json",
        "csaf_files/OT/white/2026/icsa-26-006-01.json",
    ]
    for i, path in enumerate(expected_paths):
        doc = copy.deepcopy(base_advisory)
        tracking_id = f"ADVISORY-{i}"
        doc["document"]["tracking"]["id"] = tracking_id
        doc["vulnerabilities"] = [{"cve": f"CVE-2025-{1000 + i}"}]
        url = RAW_BASE + path
        respx.get(url).mock(return_value=httpx.Response(200, json=doc))

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = CISACSAFCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "cisa-csaf"
    assert summary["sources"] == 4
    assert summary["edges"] == 4

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("advisory") == 4
    assert node_counts.get("vuln") == 4

    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("describes") == 4

    # Every edge must cite a valid, existing source row (the provenance
    # rule), so a plain join should return exactly as many rows as edges.
    joined = conn.execute(
        """
        SELECT COUNT(*) AS n
        FROM edge e JOIN source s ON s.id = e.source_id
        """
    ).fetchone()
    assert joined["n"] == 4

    net_client.close()
    conn.close()
