"""PoC-in-GitHub signal collector (nomi-sec/PoC-in-GitHub).

Actual layout discovered live (2026-09-17), which differs from the plan's
assumption of one big per-year JSON file: nomi-sec/PoC-in-GitHub instead
keeps one JSON file **per CVE** under a per-year directory, e.g.
`2025/CVE-2025-0054.json`, each containing an array of GitHub repo
metadata objects (id, full_name, html_url, created_at, stargazers_count,
forks_count, ...).

Tractability (Week 2 breadth pass, not exhaustive): rather than
downloading every per-CVE file that ever existed, this collector lists one
GitHub directory (the current calendar year) via the Contents API, takes a
bounded, most-recent-by-filename sample (`SAMPLE_SIZE` CVE files), and
fetches each one's raw JSON. This keeps a single collect run to
`SAMPLE_SIZE + 1` HTTP requests. Bump `SAMPLE_SIZE` or add a second
year's directory in a later pass if broader coverage is wanted.

Writes one `signal` row per (cve, repo) pair: signal_type='poc_repo_created',
ref=repo html_url, observed_at=repo created_at, meta carries star/fork
counts for Week 3's PoC-corroboration-tier logic to consume.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import ClassVar

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord
from strata.model import store

OWNER = "nomi-sec"
REPO = "PoC-in-GitHub"
BRANCH = "master"

CONTENTS_URL_TMPL = (
    f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{{year}}?ref={BRANCH}"
)
RAW_BASE = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/"

# Bounded sample size per Week 2 scope note above.
SAMPLE_SIZE = 50


class PoCGitHubCollector(Collector):
    """Collector for nomi-sec/PoC-in-GitHub -> the `signal` table."""

    source_name: ClassVar[str] = "poc-github"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        year = str(datetime.now(UTC).year)
        listing_url = CONTENTS_URL_TMPL.format(year=year)
        listing_fr = self._net.fetch(listing_url, source=self.source_name, offline=offline)
        entries = json.loads(listing_fr.content)

        names = sorted(
            (e["name"] for e in entries if e.get("name", "").endswith(".json")),
            reverse=True,
        )[:SAMPLE_SIZE]

        results: list[net.FetchResult] = []
        for name in names:
            url = f"{RAW_BASE}{year}/{name}"
            fr = self._net.fetch(url, source=self.source_name, offline=offline)
            fr.cve = name[: -len(".json")]  # type: ignore[attr-defined]
            results.append(fr)
        return results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        cve = getattr(fetch_result, "cve", None)
        if cve is None:
            return []
        try:
            repos = json.loads(fetch_result.content)
        except json.JSONDecodeError:
            return []
        records = []
        for repo in repos:
            if not isinstance(repo, dict) or not repo.get("html_url"):
                continue
            records.append(
                {
                    "cve": cve,
                    "repo": repo,
                    "_fetch_result": fetch_result,
                }
            )
        return records

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], SourceRecord]:
        fetched_at = datetime.now(UTC).isoformat()
        source = SourceRecord(
            id=f"poc-github-{fetched_at[:10]}",
            name=self.source_name,
            url=f"https://github.com/{OWNER}/{REPO}",
            fetched_at=fetched_at,
            sha256=None,
            http_status=None,
        )

        self._signal_rows: list[dict] = []
        for record in raw_records:
            cve = record["cve"]
            repo = record["repo"]
            html_url = repo["html_url"]
            signal_id = f"poc-github--{cve}--{repo.get('id', html_url)}"
            self._signal_rows.append(
                {
                    "id": signal_id,
                    "cve": cve,
                    "source": self.source_name,
                    "signal_type": "poc_repo_created",
                    "ref": html_url,
                    "observed_at": repo.get("created_at") or fetched_at,
                    "meta": json.dumps(
                        {
                            "stars": repo.get("stargazers_count"),
                            "forks": repo.get("forks_count"),
                            "full_name": repo.get("full_name"),
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
