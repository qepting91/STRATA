"""Tests for strata.normalize.corpus.load_corpus against synthetic fixtures.

Uses hand-written synthetic corpus fixtures (tests/fixtures/corpus,
tests/fixtures/corpus_bad_citation), NOT the real sylvanite/voltzite/
kamacite files (authored separately for citation-accuracy reasons).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strata.model import store
from strata.normalize.corpus import CitationNotFoundError, load_corpus


def test_load_corpus_normal_group_lands_nodes_and_edges(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    conn = store.get_connection(tmp_path / "strata.db")

    summary = load_corpus(conn, corpus_dir=fixtures_dir / "corpus")

    assert "alpha" in summary.groups_loaded
    assert "beta" in summary.groups_loaded
    # beta is referenced by alpha's hands_off_to AND has its own file, so
    # it must be fully loaded, not stub-created.
    assert "beta" not in summary.groups_stubbed
    # unknown_group has no corpus file -> stub-created.
    assert summary.groups_stubbed == ["unknown_group"]

    node_counts = store.count_nodes_by_type(conn)
    assert node_counts.get("group") == 3  # alpha, beta, unknown_group (stub)
    assert node_counts.get("sector", 0) >= 1
    assert node_counts.get("geo", 0) >= 1
    assert node_counts.get("vuln", 0) == 1
    assert node_counts.get("tool", 0) == 1
    assert node_counts.get("technique", 0) == 1

    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("hands_off_to") == 2
    assert edge_counts.get("exploits") == 1
    assert edge_counts.get("uses") == 1
    assert edge_counts.get("implements") == 1

    # Every edge cites a valid, existing source row -- the end-to-end
    # provenance check through the corpus path, not just the collector
    # path.
    total_edges = sum(edge_counts.values())
    joined = conn.execute(
        "SELECT COUNT(*) AS n FROM edge e JOIN source s ON s.id = e.source_id"
    ).fetchone()
    assert joined["n"] == total_edges

    # Stub group node has bare attrs (no naming_org etc).
    stub_row = conn.execute(
        "SELECT * FROM node WHERE id = ?", ("unknown_group",)
    ).fetchone()
    assert stub_row["label"] == "unknown_group"
    assert stub_row["attrs"] is None

    conn.close()


def test_load_corpus_unknown_citation_raises(tmp_path: Path, fixtures_dir: Path) -> None:
    conn = store.get_connection(tmp_path / "strata.db")

    with pytest.raises(CitationNotFoundError):
        load_corpus(conn, corpus_dir=fixtures_dir / "corpus_bad_citation")

    conn.close()
