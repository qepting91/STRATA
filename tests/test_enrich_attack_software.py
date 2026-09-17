"""Tests for strata.enrich.attack_software.

Builds the software index from the same fixture bundles used by
test_collect_attack.py (attack_enterprise_sample.json / attack_ics_sample.json)
via a real manifest.json + snapshot layout under a tmp data dir -- no
network, no respx -- matching how the real cached files sit on disk after
`strata collect --source attack` has run once.
"""

from __future__ import annotations

import json
from pathlib import Path

from strata.collect.attack import ENTERPRISE_URL, ICS_URL
from strata.enrich import attack_software
from strata.model import store

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _seed_manifest(data_dir: Path) -> None:
    attack_dir = data_dir / "raw" / "attack"
    snapshot_dir = attack_dir / "2026-09-17"
    snapshot_dir.mkdir(parents=True)

    enterprise_src = _FIXTURES_DIR / "attack_enterprise_sample.json"
    ics_src = _FIXTURES_DIR / "attack_ics_sample.json"
    enterprise_dst = snapshot_dir / "enterprise.json"
    ics_dst = snapshot_dir / "ics.json"
    enterprise_dst.write_text(enterprise_src.read_text(encoding="utf-8"), encoding="utf-8")
    ics_dst.write_text(ics_src.read_text(encoding="utf-8"), encoding="utf-8")

    manifest = {
        ENTERPRISE_URL: {"snapshot_path": str(enterprise_dst)},
        ICS_URL: {"snapshot_path": str(ics_dst)},
    }
    (attack_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_build_software_index_matches_real_name_and_alias(tmp_path: Path) -> None:
    _seed_manifest(tmp_path)
    index = attack_software.build_software_index(tmp_path)

    assert index["WIREFIRE"].attack_id == "S1115"
    assert index["WIREFIRE"].url == "https://attack.mitre.org/software/S1115"
    assert index["WIREFIRE"].matrix == "enterprise"
    # Matched via alias, not just primary name.
    assert index["GIFTEDVISITOR"].attack_id == "S1115"
    # Deprecated software must not be indexed.
    assert "DEPRECATED SOFTWARE" not in index


def test_build_software_index_empty_when_attack_never_collected(tmp_path: Path) -> None:
    index = attack_software.build_software_index(tmp_path)
    assert index == {}


def test_run_merges_attack_software_attrs_onto_matching_tool_node(tmp_path: Path) -> None:
    _seed_manifest(tmp_path)
    conn = store.get_connection(tmp_path / "strata.db")

    store.insert_node(
        conn,
        id="tool-wirefire",
        type="tool",
        label="WIREFIRE",
        attrs=json.dumps({"class": "webshell", "oss": False}),
        created_at="2026-01-01T00:00:00+00:00",
    )
    store.insert_node(
        conn,
        id="tool-chopper",
        type="tool",
        label="Chopper",
        attrs=json.dumps({"class": "webshell", "oss": False}),
        created_at="2026-01-01T00:00:00+00:00",
    )

    summary = attack_software.run(conn, data_dir=tmp_path)
    assert summary == {"tools_checked": 2, "tools_matched": 1}

    row = conn.execute("SELECT attrs FROM node WHERE id = 'tool-wirefire'").fetchone()
    attrs = json.loads(row["attrs"])
    assert attrs["attack_software_id"] == "S1115"
    assert attrs["attack_software_url"] == "https://attack.mitre.org/software/S1115"
    # Existing attrs (class/oss, set by the corpus loader) must survive
    # the merge, not be wiped.
    assert attrs["class"] == "webshell"

    unmatched_row = conn.execute("SELECT attrs FROM node WHERE id = 'tool-chopper'").fetchone()
    unmatched_attrs = json.loads(unmatched_row["attrs"])
    assert "attack_software_id" not in unmatched_attrs

    conn.close()
