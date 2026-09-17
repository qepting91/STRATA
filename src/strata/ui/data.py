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

from strata.hunt.runner import build_projection, load_all_hunts, run_hunt
from strata.hunt.verdicts import evaluate_verdict
from strata.model import store
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
def load_hunt_results() -> pd.DataFrame:
    """Run every hunts/*.yaml against the real graph and return a verdict table.

    Hunts are never persisted -- they are computed fresh each call (cached
    for 5 minutes at the Streamlit layer only). Returns one row per hunt:
    id, title, verdict, hypothesis, rationale, null_hypothesis, method,
    falsifies_if, insufficient_if, telemetry_gap, and a JSON-encoded
    namespace (the hunt's own computed result variables) for the
    click-through detail view.
    """
    hunts = load_all_hunts("hunts")
    conn = _connect()
    try:
        records = []
        for h in hunts:
            result = run_hunt(conn, h)
            verdict = evaluate_verdict(result.namespace, h.insufficient_if, h.falsifies_if)
            namespace = {k: v for k, v in result.namespace.items() if k != "rows"}
            records.append(
                {
                    "id": h.id,
                    "title": h.title,
                    "verdict": verdict,
                    "hypothesis": h.hypothesis.strip(),
                    "rationale": h.rationale.strip(),
                    "null_hypothesis": h.null_hypothesis.strip(),
                    "method": h.method,
                    "falsifies_if": h.falsifies_if,
                    "insufficient_if": h.insufficient_if,
                    "telemetry_gap": h.telemetry_gap.strip(),
                    "namespace_json": json.dumps(namespace, default=str),
                }
            )
        return pd.DataFrame.from_records(records)
    finally:
        conn.close()


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


@st.cache_data(ttl=300)
def load_protocol_edges() -> pd.DataFrame:
    """Return every real vuln -[:involves]-> protocol edge.

    Columns: cve, protocol, evidence (the edge's note -- which rule
    fired), source_id, year (parsed from nvd_published, for a volume-
    over-time view).
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
            if row["vuln_attrs"]:
                try:
                    attrs = json.loads(row["vuln_attrs"])
                    published = attrs.get("nvd_published")
                    if published:
                        year = int(str(published)[:4])
                except (json.JSONDecodeError, ValueError, TypeError):
                    year = None
            records.append(
                {
                    "cve": row["cve"],
                    "protocol": row["protocol"],
                    "evidence": row["evidence"],
                    "source_id": row["source_id"],
                    "year": year,
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
        latest_fetches = store.latest_fetch_times(conn)
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
            "No vendor-PSIRT collector was ever built (deferred every week) -- "
            "vendor-specific patch-latency data (needed by H010) does not exist.",
            "CSAF's collector does not extract product-tree text -- the "
            "protocol classifier runs over CVE descriptions only, not the "
            "spec's other stated input.",
            "disclosure_to_group_use / t_group_observed is not computed -- "
            "the corpus format has no first_seen date on a group's exploits "
            "entries.",
        ],
    }


@st.cache_data(ttl=300)
def load_handoff_projection() -> nx.DiGraph:
    """Return the group/tool/vuln/product handoff-model NetworkX projection.

    Reuses hunt.runner.build_projection over the same node/edge type
    filter H009's traversal and `strata graph show` use -- the Collection
    Health page's rendered graph shows exactly the same capability model
    the hunt board reasons over, not a bespoke second query.
    """
    conn = _connect()
    try:
        return build_projection(
            conn, ["group", "tool", "vuln", "product"], ["hands_off_to", "uses", "exploits"]
        )
    finally:
        conn.close()


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
