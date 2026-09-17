"""Tests for strata.collect.metasploit, mocked via respx against small fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.metasploit import COMMITS_URL_TMPL, RAW_BASE, TREE_URL, MetasploitCollector
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
def test_metasploit_extracts_cve_refs_from_module_source(tmp_path: Path) -> None:
    tree = {
        "tree": [
            {"type": "blob", "path": "modules/exploits/multi/http/example_cve.rb"},
            {"type": "blob", "path": "modules/exploits/multi/http/no_cve_here.rb"},
            {"type": "blob", "path": "modules/auxiliary/scanner/not_an_exploit.rb"},
        ]
    }
    respx.get(TREE_URL).mock(return_value=httpx.Response(200, json=tree))

    module_with_cve = (
        "class MetasploitModule < Msf::Exploit::Remote\n"
        "  def initialize(info = {})\n"
        "    super(update_info(info,\n"
        "      'References' => [\n"
        "        [ 'CVE', '2023-46805' ],\n"
        "      ]\n"
        "    ))\n"
        "  end\nend\n"
    )
    respx.get(f"{RAW_BASE}modules/exploits/multi/http/example_cve.rb").mock(
        return_value=httpx.Response(200, content=module_with_cve)
    )
    respx.get(f"{RAW_BASE}modules/exploits/multi/http/no_cve_here.rb").mock(
        return_value=httpx.Response(200, content="class Foo; end\n")
    )
    commits_url = (
        f"{COMMITS_URL_TMPL}?path=modules/exploits/multi/http/example_cve.rb"
        "&per_page=1&page=1"
    )
    respx.get(commits_url).mock(
        return_value=httpx.Response(
            200, json=[{"commit": {"committer": {"date": "2024-01-15T00:00:00Z"}}}]
        )
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = MetasploitCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "metasploit"
    assert summary["signals"] == 1

    row = conn.execute(
        "SELECT * FROM signal WHERE cve = ?", ("CVE-2023-46805",)
    ).fetchone()
    assert row is not None
    assert row["observed_at"] == "2024-01-15T00:00:00Z"
    meta = json.loads(row["meta"])
    assert meta["observed_at_is_collection_time_proxy"] is False

    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM signal g JOIN source s ON s.id = g.source_id"
    ).fetchone()
    assert joined["n"] == 1

    net_client.close()
    conn.close()
