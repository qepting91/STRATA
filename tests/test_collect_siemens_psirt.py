"""Tests for strata.collect.siemens_psirt, mocked via respx against fixtures."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.siemens_psirt import PROVIDER_METADATA_URL, SiemensPSIRTCollector
from strata.model import store


def _make_net_client(tmp_path: Path) -> net.NetClient:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("cert-portal.siemens.com\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."cert-portal.siemens.com"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    return net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )


@respx.mock
def test_siemens_psirt_collect_lands_advisory_vuln_and_describes_edge(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    provider_fixture = (fixtures_dir / "siemens_provider_metadata.json").read_text(
        encoding="utf-8"
    )
    respx.get(PROVIDER_METADATA_URL).mock(
        return_value=httpx.Response(200, content=provider_fixture)
    )

    feed_url = "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"
    feed_fixture = (fixtures_dir / "siemens_feed_sample.json").read_text(encoding="utf-8")
    respx.get(feed_url).mock(return_value=httpx.Response(200, content=feed_fixture))

    advisory_fixture = (fixtures_dir / "siemens_advisory_sample.json").read_text(
        encoding="utf-8"
    )
    respx.get("https://cert-portal.siemens.com/productcert/csaf/ssa-823812.json").mock(
        return_value=httpx.Response(200, content=advisory_fixture)
    )
    respx.get("https://cert-portal.siemens.com/productcert/csaf/ssa-019113.json").mock(
        return_value=httpx.Response(
            200,
            content=advisory_fixture.replace("SSA-823812", "SSA-019113").replace(
                "CVE-2026-89207", "CVE-2026-11111"
            ),
        )
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = SiemensPSIRTCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "siemens-psirt"
    assert summary["sources"] == 2
    assert summary["edges"] == 2

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("advisory") == 2
    assert node_counts.get("vuln") == 2

    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("describes") == 2

    # Every edge cites a valid, existing source row (the provenance rule).
    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM edge e JOIN source s ON s.id = e.source_id"
    ).fetchone()
    assert joined["n"] == 2

    # The vendor's own advisory disclosure date is the real value-add
    # here -- not just the fetch timestamp.
    advisory_row = conn.execute(
        "SELECT attrs FROM node WHERE id = 'SSA-823812'"
    ).fetchone()
    import json

    attrs = json.loads(advisory_row["attrs"])
    assert attrs["initial_release_date"] == "2026-09-16T00:00:00.000Z"
    assert attrs["vendor"] == "siemens-psirt"

    source_row = store.get_source(conn, "siemens-psirt-SSA-823812")
    assert source_row is not None
    assert source_row["name"] == "siemens-psirt"

    net_client.close()
    conn.close()
