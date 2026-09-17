"""Tests for strata.collect.attack, mocked via respx against small STIX fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.attack import ENTERPRISE_URL, ICS_URL, ATTACKCollector
from strata.model import store


def _make_net_client(tmp_path: Path) -> net.NetClient:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("raw.githubusercontent.com\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."raw.githubusercontent.com"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    return net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )


@respx.mock
def test_attack_collects_enterprise_and_ics_techniques(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    enterprise = json.loads(
        (fixtures_dir / "attack_enterprise_sample.json").read_text(encoding="utf-8")
    )
    ics = json.loads((fixtures_dir / "attack_ics_sample.json").read_text(encoding="utf-8"))
    respx.get(ENTERPRISE_URL).mock(return_value=httpx.Response(200, json=enterprise))
    respx.get(ICS_URL).mock(return_value=httpx.Response(200, json=ics))

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    collector = ATTACKCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "attack"
    assert summary["sources"] == 2  # one per matrix
    assert summary["edges"] == 0
    # 2 valid enterprise techniques (deprecated + non-attack-pattern excluded) + 1 ics
    assert summary["nodes"] == 3

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("technique") == 3

    row = conn.execute("SELECT * FROM node WHERE id = ?", ("T1190",)).fetchone()
    attrs = json.loads(row["attrs"])
    assert attrs["matrix"] == "enterprise"
    assert attrs["tactics"] == ["initial-access"]
    assert attrs["url"] == "https://attack.mitre.org/techniques/T1190/"
    # Citation markers are stripped, real description text is kept.
    assert attrs["description"].startswith("Adversaries may attempt to exploit")
    assert "Citation" not in attrs["description"]
    # Real ATT&CK descriptions embed markdown-style links
    # ("[text](url)") -- these must be flattened to plain text, since
    # raw "[text](url)" syntax corrupts the UI's HTML tooltip attribute
    # (found live: Streamlit's markdown renderer converts it into a real
    # <a> tag even inside an existing HTML attribute string).
    assert "Command and Scripting Interpreter" in attrs["description"]
    assert "[" not in attrs["description"]
    assert "](" not in attrs["description"]

    sub_row = conn.execute("SELECT * FROM node WHERE id = ?", ("T1505.003",)).fetchone()
    sub_attrs = json.loads(sub_row["attrs"])
    assert sub_attrs["url"] == "https://attack.mitre.org/techniques/T1505/003/"

    ics_row = conn.execute("SELECT * FROM node WHERE id = ?", ("T0886",)).fetchone()
    assert json.loads(ics_row["attrs"])["matrix"] == "ics"

    # Deprecated technique must not have landed.
    assert conn.execute("SELECT 1 FROM node WHERE id = ?", ("T9999",)).fetchone() is None

    net_client.close()
    conn.close()
