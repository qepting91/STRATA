"""CISA Known Exploited Vulnerabilities (KEV) catalog collector.

Single-payload feed: one shared `source` row covers the whole fetch. One
`vuln` node per CVE ID, using the raw CVE ID string as the node's natural
primary key so it dedupes cleanly against vuln nodes created by the CSAF
collector (see cisa_csaf.py).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCollector(Collector):
    """Collector for the CISA KEV catalog JSON feed."""

    source_name: ClassVar[str] = "cisa-kev"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        fr = self._net.fetch(KEV_URL, source=self.source_name, offline=offline)
        self._fetch_result = fr
        return [fr]

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        data = json.loads(fetch_result.content)
        catalog_version = data.get("catalogVersion", "unknown")
        vulnerabilities = data.get("vulnerabilities", [])

        records: list[dict] = []
        for entry in vulnerabilities:
            date_added = entry.get("dateAdded")
            if self.since is not None and date_added:
                try:
                    if date.fromisoformat(date_added) < self.since:
                        continue
                except ValueError:
                    pass
            record = dict(entry)
            record["_catalog_version"] = catalog_version
            records.append(record)
        return records

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], SourceRecord]:
        fetched_at = datetime.now(UTC).isoformat()
        fr = self._fetch_result

        catalog_version = (
            raw_records[0]["_catalog_version"] if raw_records else "unknown"
        )
        fetch_date = fetched_at[:10]
        source = SourceRecord(
            id=f"cisa-kev-{catalog_version}-{fetch_date}",
            name=self.source_name,
            url=KEV_URL,
            fetched_at=fetched_at,
            sha256=fr.sha256,
            http_status=fr.status_code,
        )

        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []
        seen_cves: set[str] = set()

        for record in raw_records:
            cve = record.get("cveID")
            if not cve or cve in seen_cves:
                continue
            seen_cves.add(cve)

            attrs = json.dumps(
                {
                    "vendor_project": record.get("vendorProject"),
                    "product": record.get("product"),
                    "vulnerability_name": record.get("vulnerabilityName"),
                    "date_added": record.get("dateAdded"),
                    "known_ransomware_campaign_use": record.get(
                        "knownRansomwareCampaignUse"
                    ),
                    "required_action": record.get("requiredAction"),
                    "due_date": record.get("dueDate"),
                },
                sort_keys=True,
            )
            nodes.append(
                NodeRecord(
                    id=cve,
                    type="vuln",
                    label=cve,
                    attrs=attrs,
                    created_at=fetched_at,
                )
            )

        return nodes, edges, source
