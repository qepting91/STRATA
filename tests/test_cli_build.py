"""End-to-end smoke test for `strata build` (corpus load + all enrichment
passes), via typer.testing.CliRunner against a temp DB and a minimal
one-group corpus fixture."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from strata.cli import app
from strata.model import store

runner = CliRunner()


def _write_minimal_corpus(corpus_dir: Path) -> None:
    (corpus_dir / "groups").mkdir(parents=True)
    (corpus_dir / "citations.yaml").write_text(
        "S-9001:\n  publisher: Test\n  url: https://example.test/report\n"
        "  retrieved: '2026-01-01'\n",
        encoding="utf-8",
    )
    (corpus_dir / "groups" / "testgroup.yaml").write_text(
        "id: testgroup\n"
        "name: TESTGROUP\n"
        "naming_org: Test\n"
        "ics_kill_chain_stage: 1\n"
        "role: initial_access_broker\n"
        "aliases: []\n"
        "targets:\n"
        "  sectors: [electric]\n"
        "  geos: [US]\n"
        "  src: S-9001\n"
        "exploits: []\n"
        "tools: []\n"
        "techniques: []\n"
        "hands_off_to: []\n",
        encoding="utf-8",
    )


def test_strata_build_runs_corpus_load_and_all_enrichment_passes(
    tmp_path: Path, monkeypatch
) -> None:
    db_path = tmp_path / "strata.db"
    corpus_dir = tmp_path / "corpus"
    _write_minimal_corpus(corpus_dir)

    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))

    # Seed a vuln node with a description (as NVD would) so the protocol
    # classifier has something to classify, plus its own source row.
    conn = store.get_connection(db_path)
    store.insert_source(
        conn, id="nvd-CVE-2024-7777", name="nvd", url=None,
        fetched_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        conn, id="CVE-2024-7777", type="vuln", label="CVE-2024-7777",
        attrs=json.dumps(
            {"description": "A Modbus write vulnerability.", "nvd_published": "2024-01-01"}
        ),
        created_at="2026-01-01T00:00:00Z",
    )
    conn.close()

    result = runner.invoke(app, ["build", "--corpus-dir", str(corpus_dir)])

    assert result.exit_code == 0, result.output
    assert "Corpus load:" in result.output
    assert "Protocol classifier:" in result.output
    assert "Purdue mapping:" in result.output
    assert "Weaponization timeline:" in result.output
    assert "Adversary consensus" in result.output

    conn = store.get_connection(db_path)
    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("involves") == 1
    assert edge_counts.get("targets") == 2  # sector + geo, from testgroup.yaml
    conn.close()
