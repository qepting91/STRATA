"""Tests for strata.collect.cisa_kev, mocked via respx against the fixture."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.cisa_kev import KEV_URL, CISAKEVCollector
from strata.model import store


@respx.mock
def test_kev_collect_lands_expected_nodes_and_source(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    fixture = json.loads((fixtures_dir / "kev_sample.json").read_text(encoding="utf-8"))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=fixture))

    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("www.cisa.gov\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."www.cisa.gov"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"

    net_client = net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )
    conn = store.get_connection(tmp_path / "strata.db")

    collector = CISAKEVCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "cisa-kev"
    assert summary["sources"] == 1
    assert summary["nodes"] == 4  # four distinct CVEs in the fixture

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("vuln") == 4
    assert store.count_sources(conn) == 1

    row = conn.execute(
        "SELECT * FROM node WHERE id = ?", ("CVE-2023-46805",)
    ).fetchone()
    assert row is not None
    assert row["type"] == "vuln"

    net_client.close()
    conn.close()


@respx.mock
def test_kev_since_filter_excludes_older_entries(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    fixture = json.loads((fixtures_dir / "kev_sample.json").read_text(encoding="utf-8"))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=fixture))

    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("www.cisa.gov\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."www.cisa.gov"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"

    net_client = net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )
    conn = store.get_connection(tmp_path / "strata.db")

    collector = CISAKEVCollector(net_client)
    import datetime as dt

    collector.since = dt.date(2025, 1, 1)
    summary = collector.run(conn, offline=False)

    # Only CVE-2025-4427 and CVE-2025-31324 have dateAdded >= 2025-01-01.
    assert summary["nodes"] == 2

    net_client.close()
    conn.close()
