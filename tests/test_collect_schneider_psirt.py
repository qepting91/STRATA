"""Tests for strata.collect.schneider_psirt, mocked via respx against fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.schneider_psirt import PROVIDER_METADATA_URL, SchneiderPSIRTCollector
from strata.model import store


def _make_net_client(tmp_path: Path) -> net.NetClient:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("www.se.com\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."www.se.com"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    return net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )


@respx.mock
def test_schneider_psirt_collect_lands_advisory_vulns_and_describes_edges(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    provider_fixture = (fixtures_dir / "schneider_provider_metadata.json").read_text(
        encoding="utf-8"
    )
    respx.get(PROVIDER_METADATA_URL).mock(
        return_value=httpx.Response(200, content=provider_fixture)
    )

    changes_url = "https://www.se.com/.well-known/csaf/changes.csv"
    changes_fixture = (fixtures_dir / "schneider_changes_sample.csv").read_text(
        encoding="utf-8"
    )
    respx.get(changes_url).mock(return_value=httpx.Response(200, content=changes_fixture))

    advisory_fixture = (fixtures_dir / "schneider_advisory_sample.json").read_text(
        encoding="utf-8"
    )
    respx.get("https://www.se.com/.well-known/csaf/2026/sevd-2026-251-01.json").mock(
        return_value=httpx.Response(200, content=advisory_fixture)
    )
    respx.get("https://www.se.com/.well-known/csaf/2026/sevd-2026-132-02.json").mock(
        return_value=httpx.Response(
            200,
            content=advisory_fixture.replace("SEVD-2026-251-01", "SEVD-2026-132-02")
            .replace("CVE-2026-19233", "CVE-2026-22222")
            .replace("CVE-2026-8044", "CVE-2026-33333"),
        )
    )
    respx.get("https://www.se.com/.well-known/csaf/2025/sevd-2025-224-05.json").mock(
        return_value=httpx.Response(
            200,
            content=advisory_fixture.replace("SEVD-2026-251-01", "SEVD-2025-224-05")
            .replace("CVE-2026-19233", "CVE-2025-44444")
            .replace("CVE-2026-8044", "CVE-2025-55555"),
        )
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = SchneiderPSIRTCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "schneider-psirt"
    assert summary["sources"] == 3
    # Each of the 3 advisories in the fixture set has 2 CVEs -> 6 describes edges.
    assert summary["edges"] == 6

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("advisory") == 3
    assert node_counts.get("vuln") == 6

    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("describes") == 6

    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM edge e JOIN source s ON s.id = e.source_id"
    ).fetchone()
    assert joined["n"] == 6

    advisory_row = conn.execute(
        "SELECT attrs FROM node WHERE id = 'SEVD-2026-251-01'"
    ).fetchone()
    attrs = json.loads(advisory_row["attrs"])
    assert attrs["initial_release_date"] == "2026-09-08T07:00:00.000Z"
    assert attrs["vendor"] == "schneider-psirt"

    source_row = store.get_source(conn, "schneider-psirt-SEVD-2026-251-01")
    assert source_row is not None
    assert source_row["name"] == "schneider-psirt"

    net_client.close()
    conn.close()
