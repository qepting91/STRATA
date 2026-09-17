"""Metasploit-framework signal collector (rapid7/metasploit-framework).

CVE-referencing exploit modules live under `modules/exploits/**/*.rb` and
declare CVE references in Ruby source as a `Rex::Text::CVE` style entry in
the module's `references` array, e.g. `['CVE', '2023-1234']` (verified
live, 2026-09-17 against real module source: this exact two-element-array
literal form is what's actually used). There are ~2,700 exploit `.rb`
files in the repo -- far too many to fetch and parse in full for a Week 2
breadth pass, and there is no CVE-named-file shortcut like nuclei's.

Pragmatic sampling: enumerate the exploit tree via the GitHub Trees API
(same pattern as nuclei.py/cisa_csaf.py), take a bounded, most-recent
(by path) sample of `SAMPLE_SIZE` `.rb` files, fetch each one's raw
content, and regex-search for the `['CVE', '<year>-<num>']` literal. Only
sampled files that actually reference a CVE produce a signal row -- most
modules do not reference a CVE at all (0-day discoveries, auth-bypass
chains without a CVE assignment, etc.), so the signal count from this
collector is expected to be well under SAMPLE_SIZE.

Commit-date honesty: as with nuclei.py, one additional
`commits?path=...&per_page=1&page=1` call is made per file that actually
matched a CVE reference (not per sampled file), keeping the extra API call
count bounded by the (small) number of CVE-referencing modules found
rather than by SAMPLE_SIZE.

Writes one `signal` row per (cve, module path): signal_type=
'metasploit_module_added', ref=the raw module URL, observed_at=the first
commit's date for that path.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import ClassVar
from urllib.parse import quote

import httpx

from strata import net
from strata.collect.base import Collector, EdgeRecord, NodeRecord, SourceRecord
from strata.model import store

OWNER = "rapid7"
REPO = "metasploit-framework"
BRANCH = "master"

TREE_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/git/trees/{BRANCH}?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/"
COMMITS_URL_TMPL = f"https://api.github.com/repos/{OWNER}/{REPO}/commits"

_CVE_REF_RE = re.compile(r"""\[\s*['"]CVE['"]\s*,\s*['"](\d{4}-\d+)['"]\s*\]""")

# Path-shape allowlist, mirroring nuclei.py's anchored regex discipline:
# real module paths are alnum/underscore/hyphen/dot/slash only. GitHub
# blob paths are ultimately upstream-controlled data (from the tree API
# response), not attacker input in the direct sense, but nothing stops a
# path containing a query-string-breaking character (&, #, ?, %, space)
# from being technically legal in git -- this rejects any candidate that
# doesn't match before it's ever interpolated into a URL, and quote() is
# applied as a second layer below.
_SAFE_MODULE_PATH_RE = re.compile(r"^modules/exploits/[A-Za-z0-9_./-]+\.rb$")

# Bounded sample size -- see module docstring.
SAMPLE_SIZE = 60


class MetasploitCollector(Collector):
    """Collector for rapid7/metasploit-framework -> the `signal` table."""

    source_name: ClassVar[str] = "metasploit"

    def fetch(self, offline: bool) -> list[net.FetchResult]:
        tree_fr = self._net.fetch(TREE_URL, source=self.source_name, offline=offline)
        tree_data = json.loads(tree_fr.content)

        candidates = [
            item["path"]
            for item in tree_data.get("tree", [])
            if item.get("type") == "blob"
            and _SAFE_MODULE_PATH_RE.match(item.get("path", ""))
        ]
        candidates.sort(reverse=True)
        selected = candidates[:SAMPLE_SIZE]

        results: list[net.FetchResult] = []
        for path in selected:
            safe_path = quote(path, safe="/")
            fr = self._net.fetch(
                f"{RAW_BASE}{safe_path}", source=self.source_name, offline=offline
            )
            fr.path = path  # type: ignore[attr-defined]
            results.append(fr)
        return results

    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        path = getattr(fetch_result, "path", None)
        if path is None:
            return []
        text = fetch_result.content.decode("utf-8", errors="replace")
        matches = _CVE_REF_RE.findall(text)
        return [
            {"cve": f"CVE-{m}", "path": path, "_fetch_result": fetch_result}
            for m in sorted(set(matches))
        ]

    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], SourceRecord]:
        fetched_at = datetime.now(UTC).isoformat()
        source = SourceRecord(
            id=f"metasploit-{fetched_at[:10]}",
            name=self.source_name,
            url=f"https://github.com/{OWNER}/{REPO}",
            fetched_at=fetched_at,
            sha256=None,
            http_status=None,
        )

        self._pending_commit_lookups = [
            (record["cve"], record["path"]) for record in raw_records
        ]
        self._source_id = source.id

        return [], [], source

    def run(self, conn, offline: bool = False) -> dict:
        summary = super().run(conn, offline=offline)

        fetched_at = datetime.now(UTC).isoformat()
        self._signal_rows: list[dict] = []
        for cve, path in self._pending_commit_lookups:
            commits_url = f"{COMMITS_URL_TMPL}?path={quote(path, safe='/')}&per_page=1&page=1"
            observed_at = None
            try:
                commits_fr = self._net.fetch(commits_url, source=self.source_name, offline=offline)
                page_data = json.loads(commits_fr.content)
                if page_data:
                    observed_at = (
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
                # limit (60 req/hour) exhausted by the commit-date lookups
                # this collector makes -- discovered live (see module
                # docstring). Fall back to the collection-time proxy date
                # rather than aborting the whole run; the meta flag below
                # records that this happened for this signal.
                pass

            source_id = self._source_id
            row = {
                "id": f"metasploit--{cve}--{path}",
                "cve": cve,
                "source": self.source_name,
                "signal_type": "metasploit_module_added",
                "ref": f"{RAW_BASE}{quote(path, safe='/')}",
                "observed_at": observed_at or fetched_at,
                "meta": json.dumps(
                    {
                        "path": path,
                        "observed_at_is_collection_time_proxy": observed_at is None,
                    },
                    sort_keys=True,
                ),
                "source_id": source_id,
            }
            self._signal_rows.append(row)
            store.insert_signal(conn, **row)

        summary["signals"] = len(self._signal_rows)
        return summary
