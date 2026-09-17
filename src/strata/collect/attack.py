"""MITRE ATT&CK enterprise + ICS technique collector.

Fetches the two STIX 2.1 bundles published at the "master" ref of
mitre-attack/attack-stix-data on GitHub:

  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
      enterprise-attack/enterprise-attack.json
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
      ics-attack/ics-attack.json

Investigated alternative: the repo also keeps per-release versioned copies
under subdirectories (e.g. enterprise-attack/enterprise-attack-16.1.json).
Verified live (2026-09-17) that the unversioned "master"-ref path above
resolves and returns the current bundle for both matrices, so this
collector uses that directly rather than querying the GitHub API for the
latest versioned filename -- one fewer API call per run, and MITRE
maintains this exact path as the "current" pointer.

Only `technique` nodes are created here (id = the ATT&CK ID such as
`T1190`, taken from `external_references` where `source_name ==
"mitre-attack"`). No edges: group<->technique relationships come from the
corpus loader (`normalize/corpus.py`), not from ATT&CK content itself.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord

ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
ICS_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "ics-attack/ics-attack.json"
)

_MATRIX_BY_URL = {
    ENTERPRISE_URL: "enterprise",
    ICS_URL: "ics",
}


class ATTACKCollector(Collector):
    """Collector for MITRE ATT&CK enterprise + ICS technique nodes."""

    source_name: ClassVar[str] = "attack"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        results = []
        for url in (ENTERPRISE_URL, ICS_URL):
            fr = self._net.fetch(url, source=self.source_name, offline=offline)
            fr.matrix = _MATRIX_BY_URL[url]  # type: ignore[attr-defined]
            results.append(fr)
        return results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        data = json.loads(fetch_result.content)
        matrix = getattr(fetch_result, "matrix", "enterprise")
        records: list[dict] = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue
            attack_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break
            if not attack_id:
                continue
            tactics = [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("phase_name")
            ]
            records.append(
                {
                    "attack_id": attack_id,
                    "name": obj.get("name"),
                    "matrix": matrix,
                    "tactics": tactics,
                    "_fetch_result": fetch_result,
                }
            )
        return records

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], list[SourceRecord]]:
        fetched_at = datetime.now(UTC).isoformat()

        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []
        sources: dict[str, SourceRecord] = {}
        seen_ids: set[str] = set()

        for record in raw_records:
            fr: net.FetchResult = record["_fetch_result"]
            matrix = record["matrix"]
            source_id = f"attack-{matrix}"
            if source_id not in sources:
                sources[source_id] = SourceRecord(
                    id=source_id,
                    name=self.source_name,
                    url=fr.url,
                    fetched_at=fetched_at,
                    sha256=fr.sha256,
                    http_status=fr.status_code,
                )

            attack_id = record["attack_id"]
            # A technique id can appear once per matrix (enterprise + ics
            # share some technique ids); the last one wins on conflict,
            # consistent with insert_node's upsert semantics elsewhere.
            dedupe_key = f"{attack_id}:{matrix}"
            if dedupe_key in seen_ids:
                continue
            seen_ids.add(dedupe_key)

            attrs = json.dumps(
                {
                    "name": record["name"],
                    "matrix": matrix,
                    "tactics": record["tactics"],
                },
                sort_keys=True,
            )
            nodes.append(
                NodeRecord(
                    id=attack_id,
                    type="technique",
                    label=record["name"] or attack_id,
                    attrs=attrs,
                    created_at=fetched_at,
                )
            )

        return nodes, edges, list(sources.values())
