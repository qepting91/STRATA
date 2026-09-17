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
    assert node_counts.get("vuln", 0) == 2
    assert node_counts.get("tool", 0) == 1
    assert node_counts.get("technique", 0) == 1

    edge_counts = store.count_edges_by_type(conn)
    assert edge_counts.get("hands_off_to") == 2
    assert edge_counts.get("exploits") == 2
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


def test_exploits_edge_note_carries_first_seen_when_present(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    """An Exploit entry with first_seen produces an edge whose note is that
    date string; one without first_seen produces note=None."""
    conn = store.get_connection(tmp_path / "strata.db")
    load_corpus(conn, corpus_dir=fixtures_dir / "corpus")

    with_note = conn.execute(
        "SELECT note FROM edge WHERE id = ?",
        ("alpha--exploits--CVE-2024-0001",),
    ).fetchone()
    assert with_note["note"] == "2024-01-15"

    without_note = conn.execute(
        "SELECT note FROM edge WHERE id = ?",
        ("alpha--exploits--CVE-2024-0002",),
    ).fetchone()
    assert without_note["note"] is None

    conn.close()


def test_load_corpus_unknown_citation_raises(tmp_path: Path, fixtures_dir: Path) -> None:
    conn = store.get_connection(tmp_path / "strata.db")

    with pytest.raises(CitationNotFoundError):
        load_corpus(conn, corpus_dir=fixtures_dir / "corpus_bad_citation")

    conn.close()


def test_real_corpus_azurite_pyroxene_corrected_to_stage_2(tmp_path: Path) -> None:
    """AZURITE and PYROXENE were corrected from Stage 1 -> Stage 2 this
    session (both are explicitly named Stage 2 in the Dragos 2026 OT/ICS
    Cybersecurity Year in Review's own "About" sections, cited S-0012) --
    against the project's own real corpus/, not a synthetic fixture,
    since this is a real, load-bearing accuracy correction."""
    import json

    conn = store.get_connection(tmp_path / "strata.db")
    load_corpus(conn, corpus_dir=Path("corpus"))

    for group_id in ("azurite", "pyroxene"):
        row = conn.execute(
            "SELECT attrs FROM node WHERE id = ?", (group_id,)
        ).fetchone()
        attrs = json.loads(row["attrs"])
        assert attrs["ics_kill_chain_stage"] == 2, group_id

    conn.close()


def test_real_corpus_sylvanite_godzilla_and_frp_share_tool_ids_across_groups(
    tmp_path: Path,
) -> None:
    """SYLVANITE's newly-added Godzilla/frp tool entries (S-0012) must
    slug to the SAME tool node ids that AZURITE's existing Godzilla entry
    and VOLTZITE's existing frp entry already produce -- otherwise any
    cross-group tool-sharing analysis would see 4 distinct tools instead
    of 2 real shared ones. normalize/corpus.py's slugging is
    f"tool-{name.lower().replace(' ', '_')}", so this is really just
    confirming "Godzilla"/"frp" (as spelled in each group's own YAML)
    produce identical slugs regardless of casing/spelling differences."""
    conn = store.get_connection(tmp_path / "strata.db")
    load_corpus(conn, corpus_dir=Path("corpus"))

    godzilla_users = {
        row["src_id"]
        for row in conn.execute(
            "SELECT src_id FROM edge WHERE type = 'uses' AND dst_id = 'tool-godzilla'"
        ).fetchall()
    }
    assert godzilla_users == {"sylvanite", "azurite"}

    frp_users = {
        row["src_id"]
        for row in conn.execute(
            "SELECT src_id FROM edge WHERE type = 'uses' AND dst_id = 'tool-frp'"
        ).fetchall()
    }
    assert frp_users == {"sylvanite", "voltzite"}

    conn.close()
