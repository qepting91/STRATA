"""Tests for strata.collect.nuclei, mocked via respx against small fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.nuclei import COMMITS_URL_TMPL, RAW_BASE, TREE_URL, NucleiCollector
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
def test_nuclei_writes_signal_rows_with_commit_dates(tmp_path: Path) -> None:
    tree = {
        "tree": [
            {"type": "blob", "path": "http/cves/2025/CVE-2025-0054.yaml"},
            {"type": "blob", "path": "http/cves/2024/CVE-2024-1234.yaml"},
            {"type": "blob", "path": "http/misc/not-a-cve.yaml"},
            {"type": "tree", "path": "http/cves/2025"},
        ]
    }
    respx.get(TREE_URL).mock(return_value=httpx.Response(200, json=tree))

    for path, date in [
        ("http/cves/2025/CVE-2025-0054.yaml", "2025-04-20T00:00:00Z"),
        ("http/cves/2024/CVE-2024-1234.yaml", "2024-02-01T00:00:00Z"),
    ]:
        commits_url = f"{COMMITS_URL_TMPL}?path={path}&per_page=1&page=1"
        respx.get(commits_url).mock(
            return_value=httpx.Response(
                200, json=[{"commit": {"committer": {"date": date}}}]
            )
        )
        respx.get(f"{RAW_BASE}{path}").mock(
            return_value=httpx.Response(200, content="id: test\n")
        )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = NucleiCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "nuclei"
    assert summary["signals"] == 2

    row = conn.execute(
        "SELECT * FROM signal WHERE cve = ?", ("CVE-2025-0054",)
    ).fetchone()
    assert row["observed_at"] == "2025-04-20T00:00:00Z"
    meta = json.loads(row["meta"])
    assert meta["observed_at_is_collection_time_proxy"] is False

    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM signal g JOIN source s ON s.id = g.source_id"
    ).fetchone()
    assert joined["n"] == 2

    net_client.close()
    conn.close()
