"""FIRST.org EPSS (Exploit Prediction Scoring System) collector.

Host/URL correction: the engineering spec's illustrative
`epss.cyentia.com` host is stale. The current, verified live (2026-09-17)
EPSS API is `https://api.first.org/data/v1/epss`, which supports batching
many CVEs into a single request via a comma-separated `cve=` query param
(confirmed against the real endpoint), so this collector does one HTTP
call for the whole batch rather than one per CVE (unlike NVD, whose API
has no such batching for arbitrary CVE lists).

Scope decision (Week 2, matching NVD's): fetches EPSS scores only for CVEs
already present as `vuln` nodes in the graph, for the current date --
not a historical daily backfill (deferred to a later week, per the spec's
own note that EPSS's daily CSVs are retrievable historically in one pass
once that is worth doing).

Writes one `metric_observation` row per CVE for `metric_name='epss'`, and
a second row for `metric_name='epss_percentile'` (the API always returns
both `epss` and `percentile` fields, in practice). `model_version` is left
None: the current `api.first.org/data/v1/epss` response does not include a
model-generation field in its per-row or metadata payload (verified
live) -- unlike the spec's illustrative `epss_v4` -- so there is nothing
honest to record here without an extra out-of-band lookup. This is a
documented Week 2 gap; a later pass could hit FIRST's model-changelog
page and hardcode the current generation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord
from strata.model import store

EPSS_URL = "https://api.first.org/data/v1/epss"

# Batch size for the comma-separated `cve=` param. FIRST's API paginates
# results (default limit=100 per the `limit`/`offset` fields it returns),
# so requests are additionally chunked to stay within a single page.
BATCH_SIZE = 100


class EPSSCollector(Collector):
    """Collector for FIRST.org EPSS scores, filtered to known vuln nodes."""

    source_name: ClassVar[str] = "epss"

    def __init__(self, net_client: net.NetClient | None = None) -> None:
        super().__init__(net_client)
        self._cve_ids: list[str] = []

    def run(self, conn, offline: bool = False) -> dict:
        self._metric_rows: list[dict] = []
        self._cve_ids = sorted(store.get_all_vuln_cve_ids(conn))
        summary = super().run(conn, offline=offline)
        summary["metric_observations"] = self.run_metric_observations(conn)
        return summary

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        results: list[net.FetchResult] = []
        for i in range(0, len(self._cve_ids), BATCH_SIZE):
            batch = self._cve_ids[i : i + BATCH_SIZE]
            if not batch:
                continue
            url = f"{EPSS_URL}?cve={','.join(batch)}"
            fr = self._net.fetch(url, source=self.source_name, offline=offline)
            results.append(fr)
        return results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        data = json.loads(fetch_result.content)
        rows = data.get("data", [])
        return [
            {
                "cve": row.get("cve"),
                "epss": row.get("epss"),
                "percentile": row.get("percentile"),
                "date": row.get("date"),
                "_fetch_result": fetch_result,
            }
            for row in rows
            if row.get("cve")
        ]

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], SourceRecord]:
        fetched_at = datetime.now(UTC).isoformat()
        fetch_date = fetched_at[:10]
        source = SourceRecord(
            id=f"epss-{fetch_date}",
            name=self.source_name,
            url=EPSS_URL,
            fetched_at=fetched_at,
            sha256=None,
            http_status=None,
        )

        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        self._metric_rows: list[dict] = []
        for record in raw_records:
            cve = record["cve"]
            observed_at = record.get("date") or fetch_date

            if record.get("epss") is not None:
                self._metric_rows.append(
                    {
                        "id": f"{cve}-epss-{observed_at}",
                        "node_id": cve,
                        "metric_name": "epss",
                        "value": float(record["epss"]),
                        "model_version": None,
                        "observed_at": observed_at,
                        "source_id": source.id,
                    }
                )
            if record.get("percentile") is not None:
                self._metric_rows.append(
                    {
                        "id": f"{cve}-epss_percentile-{observed_at}",
                        "node_id": cve,
                        "metric_name": "epss_percentile",
                        "value": float(record["percentile"]),
                        "model_version": None,
                        "observed_at": observed_at,
                        "source_id": source.id,
                    }
                )

        return nodes, edges, source

    def run_metric_observations(self, conn) -> int:
        """Persist metric_observation rows accumulated by normalize().

        Not part of the base Collector node/edge pipeline (metric
        observations are a separate table), so this is called explicitly
        by `run()` via the override below.
        """
        count = 0
        for row in self._metric_rows:
            store.insert_metric_observation(conn, **row)
            count += 1
        return count
