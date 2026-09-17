"""Schneider Electric CPCERT CSAF PSIRT collector.

Discovery: provider-metadata.json -> distributions[].directory_url
(https://www.se.com/.well-known/csaf/) -> that directory's
CSAF-spec-standard changes.csv, a plain CSV of
"<relative-path>","<ISO-8601 timestamp>" rows (one per advisory, observed
already-recent-first live but re-sorted defensively). Both URLs verified
live this session (see vendor_csaf.py's module docstring).
"""

from __future__ import annotations

from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord
from strata.collect.vendor_csaf import (
    N_ADVISORIES,
    discover_changes_csv_urls,
    normalize_csaf_advisories,
    parse_csaf_advisory,
)

PROVIDER_METADATA_URL = "https://www.se.com/.well-known/csaf/provider-metadata.json"


class SchneiderPSIRTCollector(Collector):
    """Collector for Schneider Electric CPCERT CSAF advisories."""

    source_name: ClassVar[str] = "schneider-psirt"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        return discover_changes_csv_urls(
            self._net,
            provider_metadata_url=PROVIDER_METADATA_URL,
            source_name=self.source_name,
            offline=offline,
            n=N_ADVISORIES,
        )

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        record = parse_csaf_advisory(fetch_result, since=self.since)
        return [record] if record is not None else []

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], list[SourceRecord]]:
        return normalize_csaf_advisories(
            raw_records, source_name=self.source_name, source_id_prefix=self.source_name
        )
