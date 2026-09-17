"""MITRE ATT&CK software (malware/tool) cross-reference for corpus tools.

`collect/attack.py` already caches the two ATT&CK STIX bundles (enterprise
+ ics) under `data/raw/attack/<date>/<hash>.json`, tracked in that
collector's own manifest. This module re-reads those same cached snapshot
files (never a live fetch of its own -- if the ATT&CK collector has never
run, this enrichment pass is a documented no-op, not an error) to build a
real name/alias -> {attack_software_id, url, matrix} index over every
non-deprecated `malware`/`tool` STIX object, then matches it against every
corpus-cited `tool` node's real display label.

Matching is intentionally exact (case-insensitive) on the STIX object's own
`name` or any `x_mitre_aliases` entry -- never substring/fuzzy -- so a
match is never a guessed attribution. This means some real corpus tools
(e.g. generic webshells like "Chopper" or "SuperShell", or families ATT&CK
tracks under a different canonical name) will legitimately not match, and
that is reported honestly as "unmatched" rather than forced.

Where matched, `attack_software_id`/`attack_software_url` are merged into
the tool node's existing attrs via the standard merge-upsert
(`store.insert_node`), citing whichever matrix's cached source row
(`attack-enterprise` / `attack-ics`, already written by the ATT&CK
collector) the match came from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from strata.collect.attack import ENTERPRISE_URL, ICS_URL
from strata.model import store


@dataclass(frozen=True)
class SoftwareEntry:
    """One real ATT&CK software (malware/tool) object, indexed for matching."""

    attack_id: str
    matrix: str
    url: str


def _load_manifest(data_dir: Path) -> dict:
    manifest_path = data_dir / "raw" / "attack" / "manifest.json"
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def build_software_index(data_dir: Path | str = "data") -> dict[str, SoftwareEntry]:
    """Build a name/alias -> SoftwareEntry index from the cached ATT&CK bundles.

    Returns an empty dict (not an error) if the ATT&CK collector has never
    run -- callers must treat that as "nothing to cross-reference yet",
    matching this project's honest-gap-over-fabrication ethos.
    """
    data_dir = Path(data_dir)
    manifest = _load_manifest(data_dir)
    index: dict[str, SoftwareEntry] = {}

    for url, matrix in ((ENTERPRISE_URL, "enterprise"), (ICS_URL, "ics")):
        entry = manifest.get(url)
        if not entry or not entry.get("snapshot_path"):
            continue
        snapshot_path = Path(entry["snapshot_path"])
        if not snapshot_path.exists():
            continue
        bundle = json.loads(snapshot_path.read_text(encoding="utf-8"))
        for obj in bundle.get("objects", []):
            if obj.get("type") not in ("malware", "tool"):
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            attack_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break
            if not attack_id:
                continue
            software_entry = SoftwareEntry(
                attack_id=attack_id,
                matrix=matrix,
                url=f"https://attack.mitre.org/software/{attack_id}",
            )
            names = [obj.get("name", "")] + list(obj.get("x_mitre_aliases", []))
            for name in names:
                if not name:
                    continue
                # First match wins on a name collision across matrices --
                # deterministic, and collisions are rare/nonexistent in
                # practice since ATT&CK software names are unique.
                index.setdefault(name.upper(), software_entry)

    return index


def run(conn, data_dir: Path | str = "data") -> dict:
    """Match every corpus `tool` node's label against the ATT&CK software index.

    Returns a summary dict: {"tools_checked", "tools_matched"}.
    """
    index = build_software_index(data_dir)
    tools = store.get_all_tool_nodes(conn)
    matched = 0

    if not index:
        return {"tools_checked": len(tools), "tools_matched": 0}

    updated_at = datetime.now(UTC).isoformat()
    for tool in tools:
        entry = index.get(tool["label"].upper())
        if entry is None:
            continue
        matched += 1
        # insert_node's own merge-upsert layers these new keys onto the
        # tool's existing attrs (class/oss, set by the corpus loader) --
        # no need to re-read/merge them here.
        new_attrs = {
            "attack_software_id": entry.attack_id,
            "attack_software_url": entry.url,
            "attack_software_matrix": entry.matrix,
        }
        store.insert_node(
            conn,
            id=tool["id"],
            type="tool",
            label=tool["label"],
            attrs=json.dumps(new_attrs, sort_keys=True),
            created_at=updated_at,
        )
    conn.commit()

    return {"tools_checked": len(tools), "tools_matched": matched}
