"""Cached, read-only data-access layer for the Streamlit UI (spec section 15.3).

Every loader here opens its own mode=ro SQLite URI connection --
sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) -- never
strata.model.store.get_connection (which sets WAL/foreign_keys/runs
migrations: a writer's setup, the UI has no business doing any of that).
mode=ro is the enforcement, not a convention: the UI process physically
cannot write to the database file.

mode=ro alone does not avoid "database is locked" -- that comes from WAL
mode already being set at database-creation time by the CLI's writer
path. Deliberately NOT using immutable=1: a WAL reader still needs to
open the -shm sidecar, and immutable blocks that (see spec section
15.3's own explicit correction).

Every query here is parameterized (? placeholders bound via the params
argument) -- no filter value is ever interpolated into SQL text.

Every loader is wrapped in @st.cache_data(ttl=300) so repeat page renders
within a five-minute window do not re-hit the database, per spec section
15.3's worked example.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from urllib.parse import quote

import networkx as nx
import pandas as pd
import streamlit as st
import yaml

from strata.model import store
from strata.model.graph_ops import build_projection
from strata.normalize.hunt_hypothesis_loader import HuntHypothesisLoadError
from strata.normalize.hunt_hypothesis_loader import load_hunt_hypotheses as _load_hunt_hypotheses
from strata.normalize.hunt_hypothesis_models import HuntHypothesis
from strata.normalize.models import GroupCorpusEntry
from strata.settings import get_settings

# The set of metric names enrich/timeline.py writes -- the only mutable
# scalars the UI is allowed to show, and only via a metric_observation
# point-in-time row, per spec section 15.3's explicit "never a scalar
# column" warning (e.g. showing "today's EPSS" next to a two-year-old
# exploitation date would be exactly the bug that warning is about).
TIMELINE_METRIC_NAMES = (
    "disclosure_to_poc_days",
    "poc_to_kev_days",
    "detection_lag_days",
    "patch_available_at_kev",
)


def get_db_path() -> Path:
    """Resolve the database path.

    Reads STRATA_DB_PATH (set by `strata ui`'s subprocess launch, see
    ui/app.py) if present, else falls back to Settings().db_path -- so the
    UI can also be run directly via `streamlit run src/strata/ui/app.py`
    in a dev shell and still find the real database.
    """
    env_path = os.environ.get("STRATA_DB_PATH")
    if env_path:
        return Path(env_path)
    return get_settings().db_path


def _connect() -> sqlite3.Connection:
    """Open a fresh read-only connection to the STRATA database.

    Raises:
        sqlite3.OperationalError: If the database file does not exist --
            surfaced to the page as a clear "no data yet" state rather
            than a cryptic locked-file error.
    """
    db_path = get_db_path()
    # file: URI paths use forward slashes; quote() escapes Windows drive
    # colons/backslash-adjacent characters safely for the URI form.
    uri_path = quote(db_path.resolve().as_posix())
    conn = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


@st.cache_data(ttl=300)
def load_groups() -> pd.DataFrame:
    """Return every threat-group node as a DataFrame (id, label, attrs)."""
    conn = _connect()
    try:
        groups = store.get_all_group_nodes(conn)
        return pd.DataFrame.from_records(groups)
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_group_detail(group_id: str) -> dict:
    """Return one group's outgoing relations (targets/exploits/tools/
    techniques/hands_off_to) plus any hands_off_to edges it receives.

    Args:
        group_id: A group node id, e.g. "sylvanite".

    Returns:
        A dict with keys "outgoing" and "incoming_handoffs", each a list
        of edge-row dicts (see store.get_outgoing_edges/get_incoming_edges).
    """
    conn = _connect()
    try:
        outgoing = store.get_outgoing_edges(conn, group_id)
        incoming_handoffs = store.get_incoming_edges(conn, group_id, ["hands_off_to"])
        return {"outgoing": outgoing, "incoming_handoffs": incoming_handoffs}
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_technique_index() -> dict[str, dict]:
    """Return every ATT&CK technique node's attrs, keyed by id.

    Used by the Threat Groups page to show a group's cited technique as
    its real MITRE name/description/URL instead of a bare ID -- populated
    by `collect/attack.py`, empty (not an error) if that collector has
    never run.
    """
    conn = _connect()
    try:
        techniques = store.get_all_technique_nodes(conn)
        return {t["id"]: (t["attrs"] or {}) for t in techniques}
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_tool_index() -> dict[str, dict]:
    """Return every tool node's attrs, keyed by id.

    Used by the Threat Groups page to show a real MITRE ATT&CK software
    cross-reference link next to a group's cited tool, where
    `enrich/attack_software.py` found a real (exact name/alias) match --
    empty (not an error) if that enrichment pass has never run.
    """
    conn = _connect()
    try:
        tools = store.get_all_tool_nodes(conn)
        return {t["id"]: (t["attrs"] or {}) for t in tools}
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_node_type_counts() -> dict[str, int]:
    """Return real node counts by type, for populating the Search page's
    type filter dynamically (never a hardcoded type list)."""
    conn = _connect()
    try:
        return store.count_nodes_by_type(conn)
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_purdue_level_options() -> list[str]:
    """Return the real, distinct Purdue levels actually present on any
    classified product node, for the Search page's Purdue-level filter."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT DISTINCT json_extract(attrs, '$.purdue_level') AS level "
            "FROM node WHERE type = 'product' AND level IS NOT NULL "
            "ORDER BY level"
        ).fetchall()
        return [str(r["level"]) for r in rows]
    finally:
        conn.close()


def _node_detail_line(node_type: str, attrs: dict) -> str:
    """One-line, type-specific summary for a search-result row.

    Deliberately per-type rather than a generic attrs dump -- an analyst
    scanning results wants the one or two facts that actually distinguish
    a row of that type, not a wall of JSON.
    """
    if node_type == "group":
        role = attrs.get("role") or "(role unstated)"
        stage = attrs.get("ics_kill_chain_stage")
        stage_text = f"Stage {stage}" if stage is not None else "Stage unstated"
        return f"{role} -- {stage_text}"
    if node_type == "vuln":
        cvss = attrs.get("cvss_v31_base")
        ransomware = attrs.get("known_ransomware_campaign_use")
        parts = []
        if cvss is not None:
            parts.append(f"CVSS {cvss}")
        if ransomware:
            parts.append(f"ransomware use: {ransomware}")
        description = attrs.get("description")
        if description:
            parts.append(_truncate(description, 140) or "")
        return " -- ".join(p for p in parts if p) or "(no enrichment data)"
    if node_type == "product":
        vendor = attrs.get("vendor") or "(vendor unknown)"
        purdue = attrs.get("purdue_level")
        purdue_text = f"Purdue {purdue}" if purdue is not None else "Purdue unmapped"
        return f"{vendor} -- {purdue_text}"
    if node_type == "tool":
        tool_class = attrs.get("class") or "(class unstated)"
        software_id = attrs.get("attack_software_id")
        return f"{tool_class}" + (f" -- ATT&CK {software_id}" if software_id else "")
    if node_type == "technique":
        return _truncate(attrs.get("description"), 140) or attrs.get("matrix", "")
    if node_type == "advisory":
        return attrs.get("initial_release_date") or ""
    return ""


@st.cache_data(ttl=300)
def search_nodes(
    keyword: str,
    types: tuple[str, ...],
    purdue_level: str | None,
    ics_stage: int | None,
    ransomware_only: str | None,
    limit: int = 300,
) -> pd.DataFrame:
    """Search every node in the graph by keyword and type, with a few
    dynamic, type-conditioned filters layered on top.

    `keyword` matches (case-insensitively) against the node's own id,
    label, or raw attrs JSON text -- so a search for "modbus" finds it
    whether it appears in a CVE description, a tool name, or a technique
    name. Every filter is applied via a bound parameter, never string-
    interpolated. Returns at most `limit` rows (real total count is
    reported separately by the caller via a COUNT(*) query) -- this is a
    search results page, not an unbounded dump.
    """
    conn = _connect()
    try:
        where = ["1=1"]
        params: list[object] = []

        if types:
            placeholders = ",".join("?" for _ in types)
            where.append(f"type IN ({placeholders})")
            params.extend(types)

        if keyword:
            like = f"%{keyword}%"
            where.append("(id LIKE ? OR label LIKE ? OR attrs LIKE ?)")
            params.extend([like, like, like])

        if purdue_level:
            # purdue_level is stored as a JSON *number* (int or float,
            # e.g. 1 or 3.5), so json_extract() returns it typed as
            # integer/real -- comparing that directly to the bound TEXT
            # parameter this filter's dropdown supplies (needed since
            # Streamlit widgets return strings) never matches under
            # SQLite's strict storage-class equality rules. Found live:
            # selecting any real Purdue level returned zero rows. Cast
            # the extracted value to TEXT before comparing.
            where.append("CAST(json_extract(attrs, '$.purdue_level') AS TEXT) = ?")
            params.append(purdue_level)

        if ics_stage is not None:
            where.append("json_extract(attrs, '$.ics_kill_chain_stage') = ?")
            params.append(ics_stage)

        if ransomware_only:
            where.append("json_extract(attrs, '$.known_ransomware_campaign_use') = ?")
            params.append(ransomware_only)

        query = (
            "SELECT id, type, label, attrs FROM node WHERE "
            + " AND ".join(where)
            + " ORDER BY type, label LIMIT ?"
        )
        rows = conn.execute(query, [*params, limit]).fetchall()

        count_query = "SELECT COUNT(*) AS n FROM node WHERE " + " AND ".join(where)
        total = conn.execute(count_query, params).fetchone()["n"]

        records = []
        for row in rows:
            attrs = {}
            if row["attrs"]:
                try:
                    attrs = json.loads(row["attrs"])
                except json.JSONDecodeError:
                    attrs = {}
            if not isinstance(attrs, dict):
                attrs = {}
            records.append(
                {
                    "id": row["id"],
                    "type": row["type"],
                    "label": row["label"],
                    "detail": _node_detail_line(row["type"], attrs),
                }
            )
        df = pd.DataFrame.from_records(records)
        df.attrs["total_matches"] = total
        return df
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_node_full(node_id: str) -> dict | None:
    """Return one node's id/type/label/attrs plus its real outgoing and
    incoming edges (each with a resolvable source citation) -- the
    Search page's "inspect one result" drill-down, reusing the exact same
    store helpers the Threat Groups page uses so provenance rendering
    never drifts between pages."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, type, label, attrs FROM node WHERE id = ?", (node_id,)
        ).fetchone()
        if row is None:
            return None
        attrs = {}
        if row["attrs"]:
            try:
                attrs = json.loads(row["attrs"])
            except json.JSONDecodeError:
                attrs = {}
        return {
            "id": row["id"],
            "type": row["type"],
            "label": row["label"],
            "attrs": attrs if isinstance(attrs, dict) else {},
            "outgoing": store.get_outgoing_edges(conn, node_id),
            "incoming": store.get_incoming_edges(conn, node_id),
        }
    finally:
        conn.close()


def get_hunt_hypotheses_dir() -> str:
    """Resolve the hunt-hypotheses directory, overridable for tests.

    Reads STRATA_HUNT_HYPOTHESES_DIR (set by test_ui_pages.py to point
    at the synthetic tests/fixtures/hunt_hypotheses fixture), else falls
    back to the real corpus/hunt_hypotheses -- same override pattern as
    get_db_path() above.
    """
    return os.environ.get("STRATA_HUNT_HYPOTHESES_DIR", "corpus/hunt_hypotheses")


def get_hunt_hypotheses_citations_path() -> str:
    """Resolve the citations registry path paired with the hunt-hypotheses dir.

    Reads STRATA_HUNT_HYPOTHESES_CITATIONS (set alongside
    STRATA_HUNT_HYPOTHESES_DIR in tests, since the synthetic fixture's
    S-TEST-1 id only exists in its own small citations.yaml, not the
    real corpus/citations.yaml).
    """
    return os.environ.get("STRATA_HUNT_HYPOTHESES_CITATIONS", "corpus/citations.yaml")


@st.cache_data(ttl=300)
def load_hunt_hypotheses(
    hunt_hypotheses_dir: str | None = None,
    citations_path: str | None = None,
) -> dict[str, HuntHypothesis]:
    """Return every validated hunt-hypothesis YAML file, keyed by group_id.

    Not a database read -- these are static, hand-authored reference
    files (see normalize/hunt_hypothesis_loader.py), read directly like
    load_telemetry_matrix/load_citations above. Returns {} if the
    directory doesn't exist yet or holds no files (real state until the
    3 example groups' files are authored), rather than raising -- pages
    9's "no example yet" st.info handles that case, not a crash here.

    Args:
        hunt_hypotheses_dir: Defaults to get_hunt_hypotheses_dir()
            (env-overridable, for tests) when not given explicitly.
        citations_path: Defaults to get_hunt_hypotheses_citations_path()
            when not given explicitly.
    """
    if hunt_hypotheses_dir is None:
        hunt_hypotheses_dir = get_hunt_hypotheses_dir()
    if citations_path is None:
        citations_path = get_hunt_hypotheses_citations_path()
    try:
        return _load_hunt_hypotheses(
            hunt_hypotheses_dir=hunt_hypotheses_dir, citations_path=citations_path
        )
    except HuntHypothesisLoadError:
        # A malformed hunt-hypothesis file is itself worth surfacing, but
        # per this module's own "don't crash the page" convention
        # (see _corpus_thin_citation_groups), fail soft here rather than
        # taking down the whole Streamlit page render.
        return {}


@st.cache_data(ttl=300)
def load_timeline_metrics() -> pd.DataFrame:
    """Return every timeline-derived metric_observation row as a DataFrame.

    Point-in-time rows only (node_id, metric_name, value, observed_at,
    source_id) -- never a mutable scalar node attrs column, per spec
    section 15.3's explicit warning. Designed to render sensibly (an
    empty/near-empty DataFrame, not a crash) when a metric has only 0 or 1
    rows, which is the real current state of this project's data.
    """
    conn = _connect()
    try:
        placeholders = ",".join("?" for _ in TIMELINE_METRIC_NAMES)
        rows = conn.execute(
            f"SELECT node_id, metric_name, value, observed_at, source_id "
            f"FROM metric_observation WHERE metric_name IN ({placeholders}) "
            f"ORDER BY metric_name, node_id",
            list(TIMELINE_METRIC_NAMES),
        ).fetchall()
        return pd.DataFrame.from_records([dict(r) for r in rows])
    finally:
        conn.close()


def _truncate(text: str | None, max_len: int = 320) -> str | None:
    """Truncate free text to max_len chars with an ellipsis, or return None unchanged."""
    if not text:
        return None
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + "..."


@st.cache_data(ttl=300)
def load_protocol_edges() -> pd.DataFrame:
    """Return every real vuln -[:involves]-> protocol edge.

    Columns: cve, protocol, evidence (the edge's note -- which rule
    fired), source_id, year (parsed from nvd_published, for a volume-
    over-time view), description_excerpt (truncated NVD attrs.description),
    csaf_excerpt (truncated attrs.csaf_product_text) -- the real context
    a reader needs to see *why* the classifier matched this CVE, not just
    that it did (see enrich/protocol.py's classify(), which runs over
    exactly these two attrs).
    """
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT e.src_id AS cve, n_dst.label AS protocol, e.note AS evidence,
                   e.source_id AS source_id, n_src.attrs AS vuln_attrs
            FROM edge e
            JOIN node n_dst ON n_dst.id = e.dst_id
            JOIN node n_src ON n_src.id = e.src_id
            WHERE e.type = 'involves'
            ORDER BY e.src_id
            """
        ).fetchall()
        records = []
        for row in rows:
            year = None
            description = None
            csaf_text = None
            if row["vuln_attrs"]:
                try:
                    attrs = json.loads(row["vuln_attrs"])
                    published = attrs.get("nvd_published")
                    if published:
                        year = int(str(published)[:4])
                    description = attrs.get("description")
                    csaf_text = attrs.get("csaf_product_text")
                except (json.JSONDecodeError, ValueError, TypeError):
                    year = None
            records.append(
                {
                    "cve": row["cve"],
                    "protocol": row["protocol"],
                    "evidence": row["evidence"],
                    "source_id": row["source_id"],
                    "year": year,
                    "description_excerpt": _truncate(description),
                    "csaf_excerpt": _truncate(csaf_text),
                }
            )
        return pd.DataFrame.from_records(records)
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_validation_labels(
    path: str = "tests/fixtures/protocol_validation_labels.json",
) -> dict:
    """Read the real, checked-in 200-CVE protocol-classifier validation set.

    This is our own measured error rate, shown in the UI rather than
    buried in a README, per spec section 15.2's Protocol CVEs page
    description. Not a database read -- this file is a static, hand-
    labeled fixture, not part of the mutable graph.
    """
    p = Path(path)
    if not p.exists():
        return {"methodology": None, "labeling_summary": {}, "items": []}
    return json.loads(p.read_text(encoding="utf-8"))


@st.cache_data(ttl=300)
def load_telemetry_matrix(path: str = "config/telemetry_matrix.yaml") -> pd.DataFrame:
    """Return config/telemetry_matrix.yaml's rows, sorted by difficulty."""
    p = Path(path)
    if not p.exists():
        return pd.DataFrame(
            columns=["hunt", "telemetry_required", "typically_collected_in_ot", "difficulty"]
        )
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    rows = data.get("rows") or []
    df = pd.DataFrame.from_records(rows)
    if df.empty:
        return df
    difficulty_rank = {"low": 0, "medium": 1, "high": 2}

    def _rank(value: str) -> int:
        lowered = str(value).lower()
        for key, rank in difficulty_rank.items():
            if lowered.startswith(key):
                return rank
        return 1

    df["_difficulty_rank"] = df["difficulty"].map(_rank)
    df = df.sort_values("_difficulty_rank", ascending=False).drop(columns="_difficulty_rank")
    return df.reset_index(drop=True)


@st.cache_data(ttl=300)
def load_citations(path: str = "corpus/citations.yaml") -> dict:
    """Return corpus/citations.yaml as a dict of citation id -> fields.

    Used by components/source_footer.py to render publisher/URL/
    retrieved-date for any corpus-derived citation id (S-0001, etc.).
    """
    p = Path(path)
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


@st.cache_data(ttl=300)
def load_source(source_id: str) -> dict | None:
    """Return one `source` table row (name/url/fetched_at/...), or None.

    Used by components/source_footer.py as the fallback lookup for a
    source_id that isn't a corpus citation id (e.g. a collector-written
    row like "nvd-CVE-2023-46805").
    """
    conn = _connect()
    try:
        return store.get_source(conn, source_id)
    finally:
        conn.close()


def format_citation_label(source_id: str | None) -> str:
    """Return a short, plain-text "Publisher (date)" citation label.

    Same lookup order as components/source_footer.py's render_source_footer
    (corpus/citations.yaml first, then the source table) but returns a
    short plain string with no markdown link -- for compact table cells
    (e.g. Threat Groups' exploits/tools tables) where a full clickable
    citation footer per row would recreate the very clutter this page
    was redesigned to remove. Not itself cached -- it only calls the two
    already-cached loaders above, so a repeat call within the same
    render is cheap.
    """
    if not source_id:
        return "(none recorded)"
    citations = load_citations()
    citation = citations.get(source_id)
    if citation is not None:
        publisher = citation.get("publisher", "unknown publisher")
        retrieved = citation.get("retrieved", "unknown date")
        return f"{publisher} (retrieved {retrieved})"
    source_row = load_source(source_id)
    if source_row is not None:
        name = source_row.get("name", "unknown source")
        fetched_at = source_row.get("fetched_at", "unknown date")
        return f"{name} (fetched {fetched_at})"
    return f"{source_id} (not found in citations.yaml or source table)"


@st.cache_data(ttl=300)
def load_purdue_cve_mass() -> pd.DataFrame:
    """Return real, live CVE-mass-by-Purdue-level counts.

    Joins distinct CVEs with an ``affects`` edge to a product classified
    at a given ``purdue_level`` -- generalized to every distinct level
    actually present in config/purdue_map.yaml's classified products, not
    hardcoded to just levels 1 and 3.5, so the Analytical Frameworks
    page's chart reflects however many real levels are mapped.
    """
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT json_extract(p.attrs, '$.purdue_level') AS purdue_level,
                   COUNT(DISTINCT affects.src_id) AS cve_mass
            FROM edge AS affects
            JOIN node AS p ON p.id = affects.dst_id AND p.type = 'product'
            WHERE affects.type = 'affects'
              AND json_extract(p.attrs, '$.purdue_level') IS NOT NULL
            GROUP BY purdue_level
            ORDER BY purdue_level
            """
        ).fetchall()
        return pd.DataFrame.from_records([dict(r) for r in rows])
    finally:
        conn.close()


@st.cache_data(ttl=300)
def load_pyramid_of_pain_counts() -> dict:
    """Return real counts of STRATA's own collected data mapped onto David
    Bianco's Pyramid of Pain's 6 layers.

    Hash Values / IP Addresses / Domain Names are hardcoded to 0 -- not
    because a query returned 0 rows, but because this project has no
    table that could ever hold one (see SECURITY.md's no-malware-sample-
    handling policy: STRATA never ingests or stores IOC-level hash/IP/
    domain data by design). Network/Host Artifacts, Tools, and TTPs are
    real live queries.
    """
    conn = _connect()
    try:
        n_signal_refs = conn.execute(
            "SELECT COUNT(*) AS n FROM signal WHERE ref IS NOT NULL AND ref != ''"
        ).fetchone()["n"]
        n_tools = conn.execute(
            "SELECT COUNT(*) AS n FROM node WHERE type = 'tool'"
        ).fetchone()["n"]
        n_uses_edges = conn.execute(
            "SELECT COUNT(*) AS n FROM edge WHERE type = 'uses'"
        ).fetchone()["n"]
        n_techniques = conn.execute(
            "SELECT COUNT(*) AS n FROM node WHERE type = 'technique'"
        ).fetchone()["n"]
        n_implements_edges = conn.execute(
            "SELECT COUNT(*) AS n FROM edge WHERE type = 'implements'"
        ).fetchone()["n"]
    finally:
        conn.close()

    return {
        "hash_values": 0,
        "ip_addresses": 0,
        "domain_names": 0,
        "network_host_artifacts": n_signal_refs,
        "n_tools": n_tools,
        "n_uses_edges": n_uses_edges,
        "n_techniques": n_techniques,
        "n_implements_edges": n_implements_edges,
    }


@st.cache_data(ttl=300)
def load_collection_health() -> dict:
    """Return per-source collection health: counts, last-fetch times, and
    known gaps.

    Combines real graph statistics (node/edge/signal/metric counts, latest
    fetch per source) with a corpus-provenance-thinness check: which
    corpus group YAML files cite fewer than two distinct citation ids
    across all of their fields (targets/exploits/tools/techniques/
    hands_off_to). This is a real, honest finding from Week 3 -- most of
    the 5 groups added that week cite only their own single Dragos page,
    with no independent second source -- surfaced here rather than only
    in a README.
    """
    conn = _connect()
    try:
        node_counts = store.count_nodes_by_type(conn)
        edge_counts = store.count_edges_by_type(conn)
        signal_counts = store.count_signals_by_source(conn)
        metric_counts = store.count_metric_observations_by_name(conn)
        source_count = store.count_sources(conn)
        latest_fetches = _normalize_fetch_times(store.latest_fetch_times(conn))
    finally:
        conn.close()

    thin_groups = _corpus_thin_citation_groups()

    return {
        "node_counts": node_counts,
        "edge_counts": edge_counts,
        "signal_counts": signal_counts,
        "metric_counts": metric_counts,
        "source_count": source_count,
        "latest_fetches": latest_fetches,
        "thin_citation_groups": thin_groups,
        "known_gaps": [
            "Only 2 of 7 named vendor-PSIRT collectors are built (Siemens "
            "ProductCERT, Schneider Electric CPCERT) -- Hitachi/Cisco/Palo "
            "Alto/Fortinet/Ivanti remain uncollected. The real sample from "
            "the 2 built collectors is thin (6 Siemens + 1 Schneider "
            "computable latency points) -- too few to trust a cross-vendor "
            "patch-latency comparison.",
            "The protocol classifier now reads CSAF advisory product-tree "
            "text as well as NVD descriptions, but this only added 1 new "
            "match -- the corpus's real protocol-CVE base rate is genuinely "
            "low (3 distinct protocol-involving CVEs total).",
            "disclosure_to_group_use / t_group_observed is now computed, but "
            "only for SYLVANITE's 5 corpus exploits entries -- the other 25 "
            "of the corpus's 26 tracked groups' public sourcing never named "
            "a specific CVE to attach a first_seen date to in the first "
            "place.",
        ],
    }


@st.cache_data(ttl=300)
def load_handoff_projection() -> nx.DiGraph:
    """Return the group/tool/vuln/product handoff-model NetworkX projection,
    pruned to only nodes actually connected by a handoff-model edge.

    Reuses `model.graph_ops.build_projection` -- the same node/edge type
    filter `strata graph show` uses -- so the Collection Health page's
    rendered graph shows exactly the same capability model, not a
    bespoke second query.

    build_projection() adds every node of the declared types
    unconditionally (by design: a real edge must never be silently
    dropped just because one endpoint's type wasn't in the filter list)
    -- with node_types including "product" (2,859 nodes) and "vuln"
    (1,790), that's ~4,600+ mostly-isolated nodes with no
    hands_off_to/uses/exploits edge at all. That's fine for a traversal
    (isolated nodes never get visited), but pyvis renders and
    physics-simulates every node regardless of degree -- found live
    (froze the browser tab rendering ~4,675 nodes). Pruning isolates
    here, at the display boundary, keeps build_projection() itself
    unchanged for `strata graph show` correctness while fixing the
    actual display bug at its source.
    """
    conn = _connect()
    try:
        graph = build_projection(
            conn, ["group", "tool", "vuln", "product"], ["hands_off_to", "uses", "exploits"]
        )
        graph.remove_nodes_from(list(nx.isolates(graph)))
        return graph
    finally:
        conn.close()


def _normalize_fetch_times(latest_fetches: dict[str, str]) -> dict[str, str]:
    """Make every ``source.name -> latest fetched_at`` value unambiguously UTC.

    Every collector-written source row already stores a full
    ``YYYY-MM-DDTHH:MM:SS+00:00``-shaped timestamp (see e.g.
    collect/cisa_kev.py's ``datetime.now(UTC).isoformat()`` calls) --
    that offset is what makes it unambiguous. The one exception is the
    ``corpus`` source (normalize/corpus.py's ``_resolve_source_id``),
    whose ``fetched_at`` is ``citation.get("retrieved") or fetched_at``:
    every corpus/citations.yaml entry's ``retrieved`` field is a bare
    ``"YYYY-MM-DD"`` string (confirmed live: e.g. ``"2026-09-17"``, no
    time-of-day, no offset) -- genuinely date-only at the source, not a
    display truncation. Rendered next to every other row's full
    precision UTC timestamp, a bare date with no offset looks
    inconsistent and its timezone is ambiguous to a reader. Normalize it
    to an explicit, honest ``<date>T00:00:00+00:00 (date-only)`` label
    instead of leaving it looking like an accidentally-truncated
    timestamp.
    """
    normalized: dict[str, str] = {}
    for name, value in latest_fetches.items():
        if value and len(value) == len("YYYY-MM-DD") and value[4] == "-" and value[7] == "-":
            normalized[name] = f"{value}T00:00:00+00:00 (date-only)"
        else:
            normalized[name] = value
    return normalized


def _corpus_thin_citation_groups(corpus_dir: str = "corpus") -> list[dict]:
    """Return corpus groups whose distinct citation-id count is < 2.

    Reads corpus/groups/*.yaml directly (not the graph, which only stores
    one source_id per edge, already flattened) so this can report the
    per-group citation set size, not just an edge count.
    """
    groups_dir = Path(corpus_dir) / "groups"
    if not groups_dir.exists():
        return []

    thin: list[dict] = []
    for path in sorted(groups_dir.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            entry = GroupCorpusEntry.model_validate(raw)
        except Exception:
            # A malformed corpus file is itself a health finding, not
            # something this page should crash on.
            continue

        citation_ids: set[str] = set()
        if entry.targets is not None:
            citation_ids.add(entry.targets.src)
        for alias in entry.aliases:
            citation_ids.add(alias.src)
        for exploit in entry.exploits:
            citation_ids.add(exploit.src)
        for tool in entry.tools:
            citation_ids.add(tool.src)
        for technique in entry.techniques:
            citation_ids.add(technique.src)
        for handoff in entry.hands_off_to:
            citation_ids.add(handoff.src)

        if len(citation_ids) < 2:
            thin.append(
                {
                    "group": entry.id,
                    "n_distinct_citations": len(citation_ids),
                    "citation_ids": sorted(citation_ids),
                }
            )
    return thin
