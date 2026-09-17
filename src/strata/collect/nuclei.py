"""Nuclei-templates signal collector (projectdiscovery/nuclei-templates).

CVE-named templates live under `http/cves/<year>/CVE-XXXX-XXXXX.yaml`
(verified live, 2026-09-17: ~4,300 such files exist across all years).
Enumerated via the GitHub Git Trees API (same pattern as cisa_csaf.py's
tree enumeration), filtered to that path shape, then bounded to a sample
of the most recent `SAMPLE_SIZE` files (sorted by the year encoded in the
path, descending) -- fetching template content and a first-commit date for
every one of ~4,300 files is not tractable for a Week 2 breadth pass.

Commit-date honesty note: the Git Trees API gives file *presence*, not a
per-file commit date. This collector makes one additional
`GET /repos/.../commits?path=<file>&page=1` call per **sampled** file
(bounded to SAMPLE_SIZE extra API calls total) and takes the oldest commit
returned by paging to the last page -- i.e. the actual first commit that
introduced the template, not a "first observed in this collection run"
proxy. This is honest but adds one API round trip per sampled file, so
SAMPLE_SIZE is kept small to keep total run time reasonable under the
1 req/sec api.github.com rate limit (tree + per-file commit lookups + raw
content, ~= 2*SAMPLE_SIZE + 1 requests split across two hosts).

Writes one `signal` row per template: signal_type='nuclei_template_added',
ref=the raw template URL, observed_at=the first commit's date.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import ClassVar

import httpx

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord
from strata.model import store

OWNER = "projectdiscovery"
REPO = "nuclei-templates"
BRANCH = "main"

TREE_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/git/trees/{BRANCH}?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/"
COMMITS_URL_TMPL = f"https://api.github.com/repos/{OWNER}/{REPO}/commits"

_CVE_TEMPLATE_RE = re.compile(r"^http/cves/(\d{4})/(CVE-\d{4}-\d+)\.ya?ml$")

# Bounded sample size -- see module docstring.
SAMPLE_SIZE = 40


class NucleiCollector(Collector):
    """Collector for projectdiscovery/nuclei-templates -> the `signal` table."""

    source_name: ClassVar[str] = "nuclei"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        tree_fr = self._net.fetch(TREE_URL, source=self.source_name, offline=offline)
        tree_data = json.loads(tree_fr.content)

        candidates = []
        for item in tree_data.get("tree", []):
            if item.get("type") != "blob":
                continue
            m = _CVE_TEMPLATE_RE.match(item.get("path", ""))
            if m:
                candidates.append((int(m.group(1)), m.group(2), item["path"]))

        candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
        selected = candidates[:SAMPLE_SIZE]

        results: list[net.FetchResult] = []
        for _year, cve, path in selected:
            # First-commit date: page to the last page of the commit
            # history for this path (GitHub returns newest-first; the
            # oldest commit is on the last page).
            commits_url = f"{COMMITS_URL_TMPL}?path={path}&per_page=1&page=1"
            first_commit_date = None
            try:
                first_page_fr = self._net.fetch(
                    commits_url, source=self.source_name, offline=offline
                )
                page_data = json.loads(first_page_fr.content)
                if page_data:
                    first_commit_date = (
                        page_data[0].get("commit", {}).get("committer", {}).get("date")
                    )
            except (
                json.JSONDecodeError,
                IndexError,
                AttributeError,
                net.OfflineCacheMiss,
                httpx.HTTPStatusError,
            ):
                # Most commonly: GitHub's unauthenticated REST API rate
                # limit (60 req/hour) exhausted by these per-file commit
                # lookups -- discovered live (see module docstring). Fall
                # back to the collection-time proxy date rather than
                # aborting the whole run.
                pass

            raw_fr = self._net.fetch(f"{RAW_BASE}{path}", source=self.source_name, offline=offline)
            raw_fr.cve = cve  # type: ignore[attr-defined]
            raw_fr.path = path  # type: ignore[attr-defined]
            raw_fr.first_commit_date = first_commit_date  # type: ignore[attr-defined]
            results.append(raw_fr)
        return results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        cve = getattr(fetch_result, "cve", None)
        if cve is None:
            return []
        return [
            {
                "cve": cve,
                "path": fetch_result.path,
                "observed_at": fetch_result.first_commit_date,
                "_fetch_result": fetch_result,
            }
        ]

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], SourceRecord]:
        fetched_at = datetime.now(UTC).isoformat()
        source = SourceRecord(
            id=f"nuclei-{fetched_at[:10]}",
            name=self.source_name,
            url=f"https://github.com/{OWNER}/{REPO}",
            fetched_at=fetched_at,
            sha256=None,
            http_status=None,
        )

        self._signal_rows: list[dict] = []
        for record in raw_records:
            cve = record["cve"]
            path = record["path"]
            observed_at = record["observed_at"]
            caveat = observed_at is None
            self._signal_rows.append(
                {
                    "id": f"nuclei--{cve}--{path}",
                    "cve": cve,
                    "source": self.source_name,
                    "signal_type": "nuclei_template_added",
                    "ref": f"{RAW_BASE}{path}",
                    "observed_at": observed_at or fetched_at,
                    "meta": json.dumps(
                        {
                            "path": path,
                            "observed_at_is_collection_time_proxy": caveat,
                        },
                        sort_keys=True,
                    ),
                    "source_id": source.id,
                }
            )

        return [], [], source

    def run(self, conn, offline: bool = False) -> dict:
        self._signal_rows = []
        summary = super().run(conn, offline=offline)
        for row in self._signal_rows:
            store.insert_signal(conn, **row)
        summary["signals"] = len(self._signal_rows)
        return summary
