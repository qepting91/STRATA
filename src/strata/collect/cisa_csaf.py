"""CISA CSAF advisory collector.

github.com/cisagov/CSAF has no stable "latest N advisories" endpoint. This
collector enumerates the whole repository tree via the GitHub Git Trees
API, filters blob paths down to the current calendar year's advisory JSON
files, sorts them by the day-of-year/sequence encoded in the filename
(e.g. icsa-26-015-01.json), and takes the most recent N (a module
constant) by fetching each one's raw content from
raw.githubusercontent.com.

Known Week 1 limitation: `--since` is applied client-side, after the N-file
sample has already been fetched, using each advisory's
`document.tracking.initial_release_date`. It cannot reach further back in
time than whatever the N-file sample happens to cover.

Deviation from the original assumption: the cisagov/CSAF repository's
default branch is `develop`, not `main` (verified live against the GitHub
API on collector design). URLs below use `develop` accordingly.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord

GITHUB_OWNER = "cisagov"
GITHUB_REPO = "CSAF"
GITHUB_BRANCH = "develop"

TREE_URL = (
    f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
    f"/git/trees/{GITHUB_BRANCH}?recursive=1"
)
RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{GITHUB_BRANCH}/"

# Number of most-recent advisory files to sample. A constant per the
# Week 1 spec; there is no "latest N" API to page against.
N_ADVISORIES = 25

_FILENAME_RE = re.compile(r"-(\d{2})-(\d{3})-(\d+)\.json$")


def _extract_product_tree_text(document: dict) -> str | None:
    """Join every product name found in a CSAF document's product_tree.

    Recurses through the common ``product_tree.branches[].branches[]...``
    shape (vendor -> product_name -> product_version_range -> product,
    see tests/fixtures/csaf_advisory_sample.json), collecting each leaf
    branch's ``product.name``, and also collects the flatter alternative
    CSAF shape ``product_tree.full_product_names[].name``. Feeds
    enrich/protocol.py's classifier (spec section 6.2's other stated
    input, alongside NVD descriptions) via the vuln node's
    ``csaf_product_text`` attr.

    Args:
        document: A parsed CSAF JSON document (the whole top-level dict).

    Returns:
        A single string joining every distinct product name found (order
        preserved, first occurrence wins on duplicates), or None if the
        document has no product_tree or no names were found.
    """
    product_tree = document.get("product_tree") or {}
    names: list[str] = []

    def _walk(branches: list[dict]) -> None:
        for branch in branches:
            if not isinstance(branch, dict):
                continue
            product = branch.get("product")
            if isinstance(product, dict) and product.get("name"):
                names.append(str(product["name"]))
            sub_branches = branch.get("branches")
            if isinstance(sub_branches, list):
                _walk(sub_branches)

    top_branches = product_tree.get("branches")
    if isinstance(top_branches, list):
        _walk(top_branches)

    for fpn in product_tree.get("full_product_names") or []:
        if isinstance(fpn, dict) and fpn.get("name"):
            names.append(str(fpn["name"]))

    if not names:
        return None
    return " | ".join(dict.fromkeys(names))


def _sort_key(path: str) -> tuple[int, int, int]:
    """Best-effort chronological sort key extracted from CSAF filenames.

    CISA CSAF filenames encode a 2-digit year, 3-digit day-of-year, and a
    sequence number, e.g. `icsa-26-015-01.json` -> (26, 15, 1). Paths that
    do not match the pattern sort first (oldest).
    """
    m = _FILENAME_RE.search(path)
    if not m:
        return (0, 0, 0)
    yy, ddd, seq = m.groups()
    return (int(yy), int(ddd), int(seq))


class CISACSAFCollector(Collector):
    """Collector for CISA CSAF advisory JSON files on GitHub."""

    source_name: ClassVar[str] = "cisa-csaf"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        tree_fr = self._net.fetch(TREE_URL, source=self.source_name, offline=offline)
        tree_data = json.loads(tree_fr.content)

        year = str(datetime.now(UTC).year)
        candidates = [
            item["path"]
            for item in tree_data.get("tree", [])
            if item.get("type") == "blob"
            and item.get("path", "").startswith("csaf_files/")
            and item["path"].endswith(".json")
            and f"/{year}/" in item["path"]
        ]
        candidates.sort(key=_sort_key, reverse=True)
        selected_paths = candidates[:N_ADVISORIES]

        fetch_results: list[net.FetchResult] = []
        for path in selected_paths:
            url = RAW_BASE + path
            fr = self._net.fetch(url, source=self.source_name, offline=offline)
            fetch_results.append(fr)
        return fetch_results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        data = json.loads(fetch_result.content)
        tracking = data.get("document", {}).get("tracking", {})
        tracking_id = tracking.get("id")
        if not tracking_id:
            return []

        initial_release_date = tracking.get("initial_release_date")

        if self.since is not None and initial_release_date:
            try:
                release_dt = datetime.fromisoformat(
                    initial_release_date.replace("Z", "+00:00")
                )
                if release_dt.date() < self.since:
                    return []
            except ValueError:
                pass

        cves = sorted(
            {
                v["cve"]
                for v in data.get("vulnerabilities", [])
                if v.get("cve")
            }
        )

        return [
            {
                "tracking_id": tracking_id,
                "initial_release_date": initial_release_date,
                "title": data.get("document", {}).get("title"),
                "cves": cves,
                "csaf_product_text": _extract_product_tree_text(data),
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
        seen_vuln_nodes: set[str] = set()

        for record in raw_records:
            fr: net.FetchResult = record["_fetch_result"]
            tracking_id: str = record["tracking_id"]
            source_id = f"cisa-csaf-{tracking_id}"

            sources.append(
                SourceRecord(
                    id=source_id,
                    name=self.source_name,
                    url=fr.url,
                    fetched_at=fetched_at,
                    sha256=fr.sha256,
                    http_status=fr.status_code,
                )
            )

            nodes.append(
                NodeRecord(
                    id=tracking_id,
                    type="advisory",
                    label=record.get("title") or tracking_id,
                    attrs=json.dumps(
                        {"initial_release_date": record.get("initial_release_date")}
                    ),
                    created_at=fetched_at,
                )
            )

            product_text = record.get("csaf_product_text")
            vuln_attrs = (
                json.dumps({"csaf_product_text": product_text})
                if product_text
                else None
            )

            for cve in record["cves"]:
                if cve not in seen_vuln_nodes:
                    seen_vuln_nodes.add(cve)
                    nodes.append(
                        NodeRecord(
                            id=cve,
                            type="vuln",
                            label=cve,
                            attrs=vuln_attrs,
                            created_at=fetched_at,
                        )
                    )
                edges.append(
                    EdgeRecord(
                        id=f"{tracking_id}--describes--{cve}",
                        src_id=tracking_id,
                        dst_id=cve,
                        type="describes",
                        source_id=source_id,
                    )
                )

        return nodes, edges, sources
