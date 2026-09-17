"""NVD CVE enrichment collector.

Scope decision (Week 2): rather than backfilling the entire NVD corpus,
this collector enriches CVEs already present as vuln nodes in the graph
(seeded by KEV/CSAF) by querying NVDs cve/2.0 REST endpoint once per CVE
(cveId query param). This means a full collect run makes one HTTP request
per known CVE -- at the current graph size (about 1800 CVEs from KEV+CSAF)
that is a few thousand requests, which at the conservative 5-requests/30s
rate limit (see config/sources.toml) takes on the order of minutes to
tens of minutes. That is an accepted, documented tradeoff for Week 2; a
fuller incremental sync via NVDs lastModStartDate window API is deferred
to a later week once it is worth the added complexity.

Passing --since is not meaningful for this per-CVE-enrichment mode since
every known CVE is re-queried each run. If self.since is set, this
collector logs a one-line notice that it is ignored and proceeds anyway.

Auth: if settings.nvd_api_key is configured, it is sent via NVDs documented
apiKey request header, which unlocks the faster (50 req/30s) tier. The
rate limiter in config/sources.toml does not yet distinguish keyed vs.
keyless (see the comment there); it always applies the conservative
keyless tier for now.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord
from strata.model import store
from strata.normalize.cpe import parse_cpe23

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_CPE_PAIRS_PER_CVE = 20


class NVDCollector(Collector):
    """Collector that enriches known vuln nodes via the NVD CVE API."""

    source_name: ClassVar[str] = "nvd"

    def __init__(
        self, net_client: net.NetClient | None = None, api_key: str | None = None
    ) -> None:
        super().__init__(net_client)
        self._api_key = api_key
        self._cve_ids: list[str] = []

    def run(self, conn, offline: bool = False) -> dict:
        if self.since is not None:
            logger.info(
                "nvd collector: --since is not meaningful for per-CVE enrichment "
                "mode; ignoring and enriching all known vuln nodes"
            )
        self._cve_ids = sorted(store.get_all_vuln_cve_ids(conn))
        return super().run(conn, offline=offline)

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        headers = {"apiKey": self._api_key} if self._api_key else None
        results: list[net.FetchResult] = []
        for cve in self._cve_ids:
            url = f"{NVD_URL}?cveId={cve}"
            fr = self._net.fetch(
                url, source=self.source_name, offline=offline, extra_headers=headers
            )
            fr.cve = cve
            results.append(fr)
        return results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        try:
            data = json.loads(fetch_result.content)
        except json.JSONDecodeError:
            return []
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return []
        cve_obj = vulns[0].get("cve", {})
        return [
            {
                "cve": getattr(fetch_result, "cve", cve_obj.get("id")),
                "cve_obj": cve_obj,
                "_fetch_result": fetch_result,
            }
        ]

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], list[SourceRecord]]:
        fetched_at = datetime.now(UTC).isoformat()

        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []
        sources: list[SourceRecord] = []
        seen_products: set[str] = set()
        seen_vendors: set[str] = set()
        seen_edges: set[str] = set()

        for record in raw_records:
            cve: str = record["cve"]
            cve_obj: dict = record["cve_obj"]
            fr: net.FetchResult = record["_fetch_result"]

            source_id = f"nvd-{cve}"
            sources.append(
                SourceRecord(
                    id=source_id,
                    name=self.source_name,
                    url=f"{NVD_URL}?cveId={cve}",
                    fetched_at=fetched_at,
                    sha256=fr.sha256,
                    http_status=fr.status_code,
                )
            )

            cvss_base_score = None
            cvss_vector = None
            metrics = cve_obj.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(metric_key)
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_base_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            cwes = sorted(
                {
                    d.get("value")
                    for w in cve_obj.get("weaknesses", [])
                    for d in w.get("description", [])
                    if d.get("value")
                }
            )

            cpe_criteria: list[str] = []
            for config in cve_obj.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria")
                        if criteria:
                            cpe_criteria.append(criteria)

            vuln_attrs = json.dumps(
                {
                    "cvss_v31_base": cvss_base_score,
                    "cvss_vector": cvss_vector,
                    "cwe": cwes,
                    "nvd_published": cve_obj.get("published"),
                },
                sort_keys=True,
            )
            nodes.append(
                NodeRecord(
                    id=cve,
                    type="vuln",
                    label=cve,
                    attrs=vuln_attrs,
                    created_at=fetched_at,
                )
            )

            cpe_pairs: list[tuple[str, str]] = []
            seen_pairs_this_cve: set[tuple[str, str]] = set()
            for criteria in cpe_criteria:
                try:
                    vendor, product = parse_cpe23(criteria)
                except ValueError:
                    continue
                pair = (vendor, product)
                if pair in seen_pairs_this_cve:
                    continue
                seen_pairs_this_cve.add(pair)
                cpe_pairs.append(pair)
                if len(cpe_pairs) >= MAX_CPE_PAIRS_PER_CVE:
                    break

            for vendor, product in cpe_pairs:
                product_id = f"{vendor}_{product}"
                if product_id not in seen_products:
                    seen_products.add(product_id)
                    nodes.append(
                        NodeRecord(
                            id=product_id,
                            type="product",
                            label=product,
                            attrs=json.dumps({"vendor": vendor, "product": product}),
                            created_at=fetched_at,
                        )
                    )
                if vendor not in seen_vendors:
                    seen_vendors.add(vendor)
                    nodes.append(
                        NodeRecord(
                            id=vendor,
                            type="vendor",
                            label=vendor,
                            attrs=None,
                            created_at=fetched_at,
                        )
                    )

                made_by_id = f"{product_id}--made_by--{vendor}"
                if made_by_id not in seen_edges:
                    seen_edges.add(made_by_id)
                    edges.append(
                        EdgeRecord(
                            id=made_by_id,
                            src_id=product_id,
                            dst_id=vendor,
                            type="made_by",
                            source_id=source_id,
                        )
                    )

                affects_id = f"{cve}--affects--{product_id}"
                if affects_id not in seen_edges:
                    seen_edges.add(affects_id)
                    edges.append(
                        EdgeRecord(
                            id=affects_id,
                            src_id=cve,
                            dst_id=product_id,
                            type="affects",
                            source_id=source_id,
                        )
                    )

        return nodes, edges, sources
