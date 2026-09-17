"""Tests for strata.collect.epss, mocked via respx against a trimmed fixture."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from strata import net
from strata.collect.epss import EPSS_URL, EPSSCollector
from strata.model import store


def _make_net_client(tmp_path: Path) -> net.NetClient:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("api.first.org\n", encoding="utf-8")
    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."api.first.org"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    return net.NetClient(
        allowlist_path=allowlist_path, sources_config_path=sources_path, data_dir=data_dir
    )


@respx.mock
def test_epss_writes_metric_observations_for_known_cves(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    fixture = json.loads((fixtures_dir / "epss_sample.json").read_text(encoding="utf-8"))
    # Match any query string on the epss endpoint (the exact CVE ordering
    # in the batched `cve=` param depends on sort order of known CVEs).
    respx.get(url__regex=rf"^{EPSS_URL.replace('.', r'\.')}.*$").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    net_client = _make_net_client(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")
    for cve in ("CVE-2023-46805", "CVE-2024-21887"):
        store.insert_node(
            conn, id=cve, type="vuln", label=cve, attrs=None,
            created_at="2026-01-01T00:00:00Z",
        )

    collector = EPSSCollector(net_client)
    summary = collector.run(conn, offline=False)

    assert summary["source"] == "epss"
    assert summary["sources"] == 1
    assert summary["metric_observations"] == 4  # epss + percentile x 2 CVEs

    metric_counts = store.count_metric_observations_by_name(conn)
    assert metric_counts.get("epss") == 2
    assert metric_counts.get("epss_percentile") == 2

    row = conn.execute(
        "SELECT * FROM metric_observation WHERE node_id = ? AND metric_name = 'epss'",
        ("CVE-2023-46805",),
    ).fetchone()
    assert abs(row["value"] - 0.99986) < 1e-6
    assert row["observed_at"] == "2026-09-16"

    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM metric_observation m JOIN source s ON s.id = m.source_id"
    ).fetchone()
    assert joined["n"] == 4

    net_client.close()
    conn.close()
