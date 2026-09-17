"""Shared helpers for vendor-published CSAF PSIRT collectors.

Siemens ProductCERT and Schneider Electric CPCERT both publish real CSAF
2.0 advisory documents in the same shape CISA's own advisories use
(document.tracking.id / initial_release_date, vulnerabilities[].cve) --
verified live this session, not guessed. The only real difference from
collect/cisa_csaf.py is *discovery*: neither vendor is a GitHub repo, so
there is no Git Trees API to walk. Live inspection this session found each
vendor uses a different (but both standard, CSAF-spec-documented)
distribution mechanism:

- Siemens: a ROLIE feed (provider-metadata.json ->
  distributions[].rolie.feeds[].url -> a feed JSON whose feed.entry array
  carries one object per advisory, each with a content.src URL pointing at
  the raw advisory JSON and a published/updated timestamp usable for
  recency sorting).
- Schneider: a plain HTTP directory distribution (provider-metadata.json
  -> distributions[].directory_url -> that directory serves a
  CSAF-spec-standard changes.csv -- rows of
  "<relative-path>","<ISO-8601 timestamp>", already observed newest-first
  in this session live fetch, but re-sorted here rather than trusted,
  since the CSAF spec does not guarantee ordering).

Both discovery mechanisms converge on the same output shape this module
cares about: a list of individual advisory JSON URLs, most-recent-first,
which the two thin per-vendor collectors (siemens_psirt.py,
schneider_psirt.py) bound to a tractable sample size before fetching and
parsing each one identically to cisa_csaf.py's per-advisory logic.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from strata import net
from strata.collect.base import EdgeRecord, NodeRecord, SourceRecord

N_ADVISORIES = 30


def discover_rolie_feed_urls(
    net_client: net.NetClient,
    *,
    provider_metadata_url: str,
    source_name: str,
    offline: bool,
    n: int = N_ADVISORIES,
) -> list[net.FetchResult]:
    """Discover the N most-recent advisory URLs from a ROLIE-style feed."""
    provider_fr = net_client.fetch(provider_metadata_url, source=source_name, offline=offline)
    provider_data = json.loads(provider_fr.content)

    feed_url: str | None = None
    for distribution in provider_data.get("distributions", []):
        rolie = distribution.get("rolie")
        if rolie and rolie.get("feeds"):
            feed_url = rolie["feeds"][0].get("url")
            break
    if not feed_url:
        return []

    feed_fr = net_client.fetch(feed_url, source=source_name, offline=offline)
    feed_data = json.loads(feed_fr.content)
    entries = feed_data.get("feed", {}).get("entry", [])

    def _entry_date(entry: dict) -> str:
        return entry.get("published") or entry.get("updated") or ""

    entries.sort(key=_entry_date, reverse=True)

    advisory_urls: list[str] = []
    for entry in entries[:n]:
        content_src = entry.get("content", {}).get("src")
        if not content_src:
            for link in entry.get("link", []):
                if link.get("rel") == "self":
                    content_src = link.get("href")
                    break
        if content_src:
            advisory_urls.append(content_src)

    return [
        net_client.fetch(url, source=source_name, offline=offline) for url in advisory_urls
    ]


def discover_changes_csv_urls(
    net_client: net.NetClient,
    *,
    provider_metadata_url: str,
    source_name: str,
    offline: bool,
    n: int = N_ADVISORIES,
) -> list[net.FetchResult]:
    """Discover the N most-recent advisory URLs from a changes.csv directory."""
    provider_fr = net_client.fetch(provider_metadata_url, source=source_name, offline=offline)
    provider_data = json.loads(provider_fr.content)

    directory_url: str | None = None
    for distribution in provider_data.get("distributions", []):
        if distribution.get("directory_url"):
            directory_url = distribution["directory_url"]
            break
    if not directory_url:
        return []
    if not directory_url.endswith("/"):
        directory_url += "/"

    changes_url = directory_url + "changes.csv"
    changes_fr = net_client.fetch(changes_url, source=source_name, offline=offline)
    # errors="replace": a malformed/non-UTF-8 byte from the vendor's server
    # (found in security review as a real, if unlikely, crash risk) must
    # degrade gracefully, not abort the whole collector run over one bad
    # byte in what's otherwise a large, mostly-fine CSV.
    text = changes_fr.content.decode("utf-8", errors="replace")

    rows: list[tuple[str, str]] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        rows.append((row[0], row[1]))

    rows.sort(key=lambda r: r[1], reverse=True)

    # Plain concatenation, not urljoin(): urljoin would let an absolute or
    # protocol-relative `path` value (e.g. "https://evil.example/x" or
    # "//evil.example/x") override the host entirely. Concatenation just
    # appends `path` as a literal path segment onto directory_url's own
    # host, so the resulting URL's host is always directory_url's host --
    # and net.py's allowlist check re-validates that host at fetch time
    # regardless, so this is safe either way, but concatenation is the
    # actually-safer choice here, not an oversight (found in security
    # review; documented so a future refactor to urljoin doesn't
    # silently reintroduce a host-override path).
    advisory_urls = [directory_url + path for path, _ts in rows[:n]]

    return [
        net_client.fetch(url, source=source_name, offline=offline) for url in advisory_urls
    ]


def parse_csaf_advisory(fetch_result: net.FetchResult, since=None) -> dict | None:
    """Parse one CSAF advisory JSON document into an intermediate record."""
    data = json.loads(fetch_result.content)
    tracking = data.get("document", {}).get("tracking", {})
    tracking_id = tracking.get("id")
    if not tracking_id:
        return None

    initial_release_date = tracking.get("initial_release_date")

    if since is not None and initial_release_date:
        try:
            release_dt = datetime.fromisoformat(initial_release_date.replace("Z", "+00:00"))
            if release_dt.date() < since:
                return None
        except ValueError:
            pass

    cves = sorted({v["cve"] for v in data.get("vulnerabilities", []) if v.get("cve")})

    return {
        "tracking_id": tracking_id,
        "initial_release_date": initial_release_date,
        "title": data.get("document", {}).get("title"),
        "cves": cves,
        "_fetch_result": fetch_result,
    }


def normalize_csaf_advisories(
    raw_records: list[dict], *, source_name: str, source_id_prefix: str
) -> tuple[list[NodeRecord], list[EdgeRecord], list[SourceRecord]]:
    """Shared normalize() body for a vendor CSAF collector."""
    fetched_at = datetime.now(UTC).isoformat()

    nodes: list[NodeRecord] = []
    edges: list[EdgeRecord] = []
    sources: list[SourceRecord] = []
    seen_vuln_nodes: set[str] = set()

    for record in raw_records:
        fr: net.FetchResult = record["_fetch_result"]
        tracking_id: str = record["tracking_id"]
        source_id = f"{source_id_prefix}-{tracking_id}"

        sources.append(
            SourceRecord(
                id=source_id,
                name=source_name,
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
                    {
                        "initial_release_date": record.get("initial_release_date"),
                        "vendor": source_name,
                    }
                ),
                created_at=fetched_at,
            )
        )

        for cve in record["cves"]:
            if cve not in seen_vuln_nodes:
                seen_vuln_nodes.add(cve)
                nodes.append(
                    NodeRecord(
                        id=cve,
                        type="vuln",
                        label=cve,
                        attrs=None,
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
