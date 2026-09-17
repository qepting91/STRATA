"""Tests for strata.collect.poc_github, mocked via respx."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.poc_github import CONTENTS_URL_TMPL, RAW_BASE, PoCGitHubCollector
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
def test_poc_github_writes_signal_rows(tmp_path: Path) -> None:
    year = str(datetime.now(UTC).year)
    listing_url = CONTENTS_URL_TMPL.format(year=year)
    respx.get(listing_url).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name": "CVE-2025-0054.json", "type": "file"},
                {"name": "CVE-2025-0087.json", "type": "file"},
                {"name": "README.md", "type": "file"},
            ],
        )
    )
    respx.get(f"{RAW_BASE}{year}/CVE-2025-0054.json").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "full_name": "foo/CVE-2025-0054",
                    "html_url": "https://github.com/foo/CVE-2025-0054",
                    "created_at": "2025-04-20T16:05:07Z",
                    "stargazers_count": 3,
                    "forks_count": 0,
                }
            ],
        )
    )
    respx.get(f"{RAW_BASE}{year}/CVE-2025-0087.json").mock(
        return_value=httpx.Response(200, json=[])
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = PoCGitHubCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "poc-github"
    assert summary["signals"] == 1

    signal_counts = store.count_signals_by_source(conn)
    assert signal_counts.get("poc-github") == 1

    row = conn.execute("SELECT * FROM signal WHERE cve = ?", ("CVE-2025-0054",)).fetchone()
    assert row["ref"] == "https://github.com/foo/CVE-2025-0054"
    meta = json.loads(row["meta"])
    assert meta["stars"] == 3

    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM signal g JOIN source s ON s.id = g.source_id"
    ).fetchone()
    assert joined["n"] == 1

    net_client.close()
    conn.close()
