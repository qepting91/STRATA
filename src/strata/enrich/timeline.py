"""Weaponization timeline (spec section 6.1).

Per CVE, computes t_disclosed (the earliest of vendor/CISA CSAF advisory
initial_release_date, NVD nvd_published, and KEV date_added -- never NVD
alone, since NVD enrichment routinely lags the vendor advisory by weeks),
PoC-corroboration-tiered t_first_poc / t_first_poc_claimed, t_nuclei_template,
t_metasploit, and t_kev. Derived intervals are written as metric_observation
rows.

t_group_observed / disclosure_to_group_use (added post-Week-4): for every
`exploits` edge whose `note` column carries a real first_seen date (see
normalize/models.py's Exploit.first_seen and normalize/corpus.py), that
date is treated as t_group_observed for the CVE it targets, and
disclosure_to_group_use = t_group_observed - t_disclosed is written as a
metric_observation row, cited to the exploits edge's own source_id (the
same publisher/article that supports the first_seen claim -- real,
correct provenance, not a stand-in). This remains a real, documented
scope limitation: only SYLVANITE's 5 corpus exploits entries currently
carry a first_seen date, so this metric is not (yet) computable for any
other group's exploits claims.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime

from strata.model import store

HIGH_STAR_THRESHOLD = 10

# PoC corroboration tier (adapted pragmatically from spec section 6.1's
# fuller criteria to what strata.model.store's signal table actually
# carries in meta today):
#
#   high     -- the CVE also has an exploitdb or metasploit signal row,
#               OR a nuclei signal row, OR the poc-github signal own
#               meta.stars > 10.
#   moderate -- the poc-github signal exists but meets none of the high
#               criteria above. The spec fuller moderate criteria
#               (">1 commit and a non-README code file") needs a per-repo
#               commit/file-listing signal this project does not collect
#               (poc_github.py meta only carries stars/forks/full_name) --
#               so moderate here is the pragmatic fallback tier for any
#               poc-github signal that is not high, not the spec
#               file-content-based definition. This is a real, documented
#               limitation, not a silent simplification.
#
# t_first_poc uses high/moderate only. t_first_poc_claimed is the
# unfiltered minimum poc-github observed_at regardless of tier, reported
# side by side per the spec explicit instruction that the delta between
# them is itself a finding about OSINT data quality.
#
# Provenance rule for derived metric_observation rows: since one row
# carries exactly one source_id but an interval blends two cited facts,
# each metric cites whichever side source "completed" the measurement --
# the side whose arrival made the interval newly computable:
#   disclosure_to_poc_days -- the winning poc-github signal source_id.
#   poc_to_kev_days        -- also the poc-github signal source_id: KEV's
#                             own per-CVE source row id is not recoverable
#                             from the vuln node attrs (KEV writes one
#                             shared per-catalog-fetch source row, not a
#                             per-CVE one), so the nearest citable
#                             completing-side source is the poc-github
#                             signal that anchors t_first_poc.
#   detection_lag_days     -- the nuclei signal source_id.
#   patch_available_at_kev -- the source_id of whichever date was actually
#                             compared against t_kev: the vendor/CISA
#                             advisory's source_id if a CSAF advisory is
#                             known for this CVE, else nvd-<cve> as a
#                             fallback. Never t_kev's own source_id, since
#                             KEV has no per-CVE source row to cite (see
#                             above).

# The exact set of metric_name values this module writes -- cleared at
# the top of run() before recomputation (see the re-runnability note
# there). Keep in sync with the metric_name= arguments used below.
_DERIVED_METRIC_NAMES = (
    "disclosure_to_poc_days",
    "poc_to_kev_days",
    "detection_lag_days",
    "patch_available_at_kev",
    "disclosure_to_group_use",
)


@dataclass
class CveTimeline:
    """Computed timestamps for one CVE. All fields are date objects or None."""

    cve: str
    t_disclosed: date | None = None
    t_disclosed_src: str | None = None
    t_disclosed_source_id: str | None = None
    t_nvd_published: date | None = None
    t_vendor_advisory: date | None = None
    t_vendor_advisory_source_id: str | None = None
    t_kev: date | None = None
    t_first_poc: date | None = None
    t_first_poc_source_id: str | None = None
    t_first_poc_claimed: date | None = None
    t_nuclei_template: date | None = None
    t_nuclei_template_source_id: str | None = None
    t_metasploit: date | None = None


def _parse_date(value: str | None) -> date | None:
    """Best-effort ISO-8601 (date or datetime) string to date. None on failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None


def _advisory_initial_release_dates(conn, cve: str) -> list[tuple[date, str]]:
    """CSAF advisory initial_release_date(s) reachable via describes edges."""
    rows = conn.execute(
        """
        SELECT n.attrs AS attrs, e.source_id AS source_id
        FROM edge e
        JOIN node n ON n.id = e.src_id
        WHERE e.type = 'describes' AND e.dst_id = ? AND n.type = 'advisory'
        """,
        (cve,),
    ).fetchall()
    results: list[tuple[date, str]] = []
    for row in rows:
        if not row["attrs"]:
            continue
        try:
            attrs = json.loads(row["attrs"])
        except json.JSONDecodeError:
            continue
        d = _parse_date(attrs.get("initial_release_date"))
        if d is not None:
            results.append((d, row["source_id"]))
    return results


def _poc_corroboration_tier(conn, cve: str, poc_meta: dict) -> str:
    """Return "high" or "moderate" for a poc-github signal on this CVE."""
    other_source_rows = conn.execute(
        "SELECT source FROM signal WHERE cve = ? AND source IN "
        "('exploitdb', 'metasploit', 'nuclei')",
        (cve,),
    ).fetchall()
    if other_source_rows:
        return "high"
    stars = poc_meta.get("stars")
    if isinstance(stars, int) and stars > HIGH_STAR_THRESHOLD:
        return "high"
    return "moderate"


def compute_cve_timeline(conn, vuln: dict) -> CveTimeline:
    """Compute a CveTimeline for a single vuln node.

    Args:
        conn: An open sqlite3.Connection.
        vuln: One entry from store.get_all_vuln_nodes(conn) -- a dict with
            id, label, attrs.

    Returns:
        A populated CveTimeline (fields None where data is unavailable).
    """
    cve = vuln["id"]
    attrs = vuln.get("attrs") or {}
    timeline = CveTimeline(cve=cve)

    nvd_published = _parse_date(attrs.get("nvd_published"))
    timeline.t_nvd_published = nvd_published

    kev_date_added = _parse_date(attrs.get("date_added"))
    timeline.t_kev = kev_date_added

    advisory_dates = _advisory_initial_release_dates(conn, cve)
    vendor_advisory_date = min(advisory_dates)[0] if advisory_dates else None
    vendor_advisory_source_id = min(advisory_dates)[1] if advisory_dates else None
    timeline.t_vendor_advisory = vendor_advisory_date
    timeline.t_vendor_advisory_source_id = vendor_advisory_source_id

    candidates: list[tuple[date, str, str | None]] = []
    if vendor_advisory_date is not None:
        candidates.append((vendor_advisory_date, "csaf_advisory", vendor_advisory_source_id))
    if nvd_published is not None:
        candidates.append((nvd_published, "nvd_published", f"nvd-{cve}"))
    if kev_date_added is not None:
        candidates.append((kev_date_added, "kev_date_added", None))

    if candidates:
        candidates.sort(key=lambda c: c[0])
        winner = candidates[0]
        timeline.t_disclosed = winner[0]
        timeline.t_disclosed_src = winner[1]
        timeline.t_disclosed_source_id = winner[2]

    poc_rows = conn.execute(
        "SELECT observed_at, meta, source_id FROM signal "
        "WHERE cve = ? AND source = 'poc-github'",
        (cve,),
    ).fetchall()

    claimed_candidates: list[date] = []
    corroborated_candidates: list[tuple[date, str]] = []
    for row in poc_rows:
        d = _parse_date(row["observed_at"])
        if d is None:
            continue
        claimed_candidates.append(d)

        try:
            meta = json.loads(row["meta"]) if row["meta"] else {}
        except json.JSONDecodeError:
            meta = {}
        tier = _poc_corroboration_tier(conn, cve, meta)
        if tier in ("high", "moderate"):
            corroborated_candidates.append((d, row["source_id"]))

    if claimed_candidates:
        timeline.t_first_poc_claimed = min(claimed_candidates)
    if corroborated_candidates:
        corroborated_candidates.sort(key=lambda c: c[0])
        timeline.t_first_poc = corroborated_candidates[0][0]
        timeline.t_first_poc_source_id = corroborated_candidates[0][1]

    nuclei_rows = conn.execute(
        "SELECT observed_at, source_id FROM signal WHERE cve = ? AND source = 'nuclei'",
        (cve,),
    ).fetchall()
    nuclei_candidates = [
        (nd, row["source_id"])
        for row in nuclei_rows
        for nd in [_parse_date(row["observed_at"])]
        if nd is not None
    ]
    if nuclei_candidates:
        nuclei_candidates.sort(key=lambda c: c[0])
        timeline.t_nuclei_template = nuclei_candidates[0][0]
        timeline.t_nuclei_template_source_id = nuclei_candidates[0][1]

    metasploit_rows = conn.execute(
        "SELECT observed_at FROM signal WHERE cve = ? AND source = 'metasploit'",
        (cve,),
    ).fetchall()
    metasploit_candidates = [
        md
        for row in metasploit_rows
        for md in [_parse_date(row["observed_at"])]
        if md is not None
    ]
    if metasploit_candidates:
        timeline.t_metasploit = min(metasploit_candidates)

    return timeline


def _write_interval_metric(
    conn,
    *,
    cve: str,
    metric_name: str,
    start: date | None,
    end: date | None,
    source_id: str | None,
    fetched_at: str,
) -> bool:
    """Write a disclosure_to_poc_days-style interval metric.

    Records negative intervals rather than dropping them -- a negative
    interval (e.g. a PoC claimed to predate disclosure) is exactly the
    kind of data-quality signal spec section 6.1 warns about, not
    something to silently discard.

    Returns:
        True if a metric_observation row was written, False if either
        side was missing or no source_id was resolvable.
    """
    if start is None or end is None or source_id is None:
        return False
    value = float((end - start).days)
    store.insert_metric_observation(
        conn,
        id=f"{cve}--{metric_name}",
        node_id=cve,
        metric_name=metric_name,
        value=value,
        model_version=None,
        observed_at=fetched_at,
        source_id=source_id,
    )
    return True


def run(conn) -> dict:
    """Compute weaponization timelines for every vuln node and write
    derived metric_observation rows.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.

    Returns:
        Summary dict: cves examined, cves with a t_disclosed, metric rows
        written, and how many hit patch_available_at_kev == 0.0 (patched
        after KEV listing).
    """
    fetched_at = datetime.now(UTC).isoformat()

    # Re-runnable: clear this pass's own derived metrics first. Each
    # metric is only written when both its endpoints are available this
    # run (_write_interval_metric returns False and skips otherwise), so
    # without this a metric that becomes uncomputable on a later run
    # (e.g. a signal row it depended on was corrected or removed) would
    # leave a stale value from a previous run sitting in the table
    # forever -- the same staleness bug enrich.protocol.run() fixes for
    # `involves` edges via delete_edges_by_type().
    store.delete_metric_observations_by_names(conn, list(_DERIVED_METRIC_NAMES))

    vulns = store.get_all_vuln_nodes(conn)

    cves_with_disclosure = 0
    metrics_written = 0
    patched_after_kev = 0
    group_use_written = 0
    timelines_by_cve: dict[str, CveTimeline] = {}

    for vuln in vulns:
        cve = vuln["id"]
        tl = compute_cve_timeline(conn, vuln)
        timelines_by_cve[cve] = tl
        if tl.t_disclosed is not None:
            cves_with_disclosure += 1

        if _write_interval_metric(
            conn, cve=cve, metric_name="disclosure_to_poc_days",
            start=tl.t_disclosed, end=tl.t_first_poc,
            source_id=tl.t_first_poc_source_id, fetched_at=fetched_at,
        ):
            metrics_written += 1

        if _write_interval_metric(
            conn, cve=cve, metric_name="poc_to_kev_days",
            start=tl.t_first_poc, end=tl.t_kev,
            source_id=tl.t_first_poc_source_id, fetched_at=fetched_at,
        ):
            metrics_written += 1

        if _write_interval_metric(
            conn, cve=cve, metric_name="detection_lag_days",
            start=tl.t_first_poc, end=tl.t_nuclei_template,
            source_id=tl.t_nuclei_template_source_id, fetched_at=fetched_at,
        ):
            metrics_written += 1

        # Prefer the vendor/CISA advisory as the patch-availability signal
        # (per spec section 6.1's own patch_available_at_kev definition,
        # t_vendor_advisory <= t_kev); fall back to NVD published only if
        # no advisory is known for this CVE. Each has its own citable
        # source_id (unlike t_kev, which has none per-CVE -- see module
        # comment above), so the source_id used here always matches
        # whichever date was actually used for the comparison.
        if tl.t_vendor_advisory is not None:
            patch_date = tl.t_vendor_advisory
            patch_source_id = tl.t_vendor_advisory_source_id
        else:
            patch_date = tl.t_nvd_published
            patch_source_id = f"nvd-{cve}" if tl.t_nvd_published is not None else None

        if patch_date is not None and tl.t_kev is not None and patch_source_id:
            is_patched_before_kev = patch_date <= tl.t_kev
            store.insert_metric_observation(
                conn,
                id=f"{cve}--patch_available_at_kev",
                node_id=cve,
                metric_name="patch_available_at_kev",
                value=1.0 if is_patched_before_kev else 0.0,
                model_version=None,
                observed_at=fetched_at,
                source_id=patch_source_id,
            )
            metrics_written += 1
            if not is_patched_before_kev:
                patched_after_kev += 1

    # disclosure_to_group_use: for every exploits edge carrying a
    # first_seen date (normalize/corpus.py writes it into the edge's
    # note column), treat that date as t_group_observed for the CVE and
    # compute the interval against t_disclosed, if known. Cited to the
    # exploits edge's own source_id -- the same publisher/article that
    # supports the first_seen claim, real correct provenance.
    for edge_row in store.get_exploits_edges_with_note(conn):
        cve = edge_row["dst_id"]
        t_group_observed = _parse_date(edge_row["note"])
        if t_group_observed is None:
            continue
        tl = timelines_by_cve.get(cve)
        if tl is None or tl.t_disclosed is None:
            continue
        if _write_interval_metric(
            conn, cve=cve, metric_name="disclosure_to_group_use",
            start=tl.t_disclosed, end=t_group_observed,
            source_id=edge_row["source_id"], fetched_at=fetched_at,
        ):
            metrics_written += 1
            group_use_written += 1

    return {
        "cves_examined": len(vulns),
        "cves_with_disclosure": cves_with_disclosure,
        "metrics_written": metrics_written,
        "patched_after_kev": patched_after_kev,
        "disclosure_to_group_use_written": group_use_written,
    }
