"""SQLite data-access layer for the STRATA graph.

Enforces the project's non-negotiable provenance rule: every edge row must
carry a non-null ``source_id`` that resolves to an existing row in
``source``. This is enforced at the schema level (NOT NULL + FOREIGN KEY,
with ``PRAGMA foreign_keys=ON``) and exercised in ``tests/test_store.py``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_connection(db_path: Path | str) -> sqlite3.Connection:
    """Open a SQLite connection configured per the STRATA spec.

    Sets WAL journaling, NORMAL synchronous mode, a 5s busy timeout, and
    enables foreign-key enforcement. Runs ``schema.sql`` idempotently
    (``CREATE TABLE IF NOT EXISTS``) so callers can call this repeatedly
    without side effects beyond ensuring the schema exists.

    Args:
        db_path: Path to the SQLite database file. Parent directories are
            created if missing.

    Returns:
        An open ``sqlite3.Connection`` with row factory set to
        ``sqlite3.Row``.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")

    schema_sql = _SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema_sql)
    conn.commit()

    _migrate_edge_note_column(conn)

    return conn


def _migrate_edge_note_column(conn: sqlite3.Connection) -> None:
    """Idempotently add ``edge.note`` to a database created before this
    column existed in schema.sql (Week 1/2 databases).

    Safe to call on every connection open, including a fresh DB where
    schema.sql already declares the column (in which case this is a no-op).
    """
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(edge)").fetchall()}
    if "note" not in cols:
        conn.execute("ALTER TABLE edge ADD COLUMN note TEXT")
        conn.commit()


def insert_source(
    conn: sqlite3.Connection,
    *,
    id: str,
    name: str,
    url: str | None,
    fetched_at: str,
    sha256: str | None = None,
    http_status: int | None = None,
) -> None:
    """Insert or update a source row (upsert keyed by id).

    Args:
        conn: Open database connection.
        id: Stable identifier for this source row.
        name: Human-readable source/collector name.
        url: The URL fetched, if any.
        fetched_at: ISO-8601 timestamp of the fetch.
        sha256: SHA-256 digest of the fetched payload, if applicable.
        http_status: HTTP status code of the fetch, if applicable.
    """
    conn.execute(
        """
        INSERT INTO source (id, name, url, fetched_at, sha256, http_status)
        VALUES (:id, :name, :url, :fetched_at, :sha256, :http_status)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            url = excluded.url,
            fetched_at = excluded.fetched_at,
            sha256 = excluded.sha256,
            http_status = excluded.http_status
        """,
        {
            "id": id,
            "name": name,
            "url": url,
            "fetched_at": fetched_at,
            "sha256": sha256,
            "http_status": http_status,
        },
    )
    conn.commit()


def insert_node(
    conn: sqlite3.Connection,
    *,
    id: str,
    type: str,
    label: str,
    attrs: str | None,
    created_at: str,
) -> None:
    """Insert or update a node row (upsert-safe, keyed by id).

    On conflict, ``attrs`` is merge-upserted rather than overwritten
    wholesale: if the new ``attrs`` payload is non-``None``, it is decoded
    and shallow-merged on top of the existing node's decoded ``attrs``
    (new keys win; keys present in the existing attrs but absent from the
    new payload are preserved). This matters because multiple collectors
    (KEV, CSAF, NVD, EPSS) all touch the same ``vuln`` node id over time
    and must not clobber each other's fields. If either side's ``attrs``
    is not valid JSON, this falls back to the new value verbatim.

    Invariant this relies on: each collector writes a disjoint set of
    attrs keys (e.g. NVD writes cvss_v31_base/cvss_vector/cwe/
    nvd_published; KEV/CSAF write different named fields). This merge is
    a blind ``dict.update()`` with no per-key provenance or authority
    check -- it is a convenience denormalization, not part of the
    provenance record (edges and metric_observation rows still each cite
    their own source_id individually). If a future collector ever reuses
    an existing attrs key name, it will silently win the merge with no
    audit trail. Keep new collectors' attrs keys disjoint from existing
    ones, or extend this function with a per-key source check if that
    stops being safe to assume.

    Args:
        conn: Open database connection.
        id: Stable natural or synthetic identifier for the node.
        type: Node type; must be one of the CHECK-constrained values.
        label: Human-readable label.
        attrs: Opaque JSON-encoded attribute blob, or None.
        created_at: ISO-8601 timestamp of first observation.
    """
    merged_attrs = attrs
    if attrs is not None:
        existing = conn.execute(
            "SELECT attrs FROM node WHERE id = ?", (id,)
        ).fetchone()
        if existing is not None and existing["attrs"] is not None:
            try:
                existing_attrs = json.loads(existing["attrs"])
                new_attrs = json.loads(attrs)
                if isinstance(existing_attrs, dict) and isinstance(new_attrs, dict):
                    merged = dict(existing_attrs)
                    merged.update(new_attrs)
                    merged_attrs = json.dumps(merged, sort_keys=True)
            except (json.JSONDecodeError, TypeError):
                merged_attrs = attrs

    conn.execute(
        """
        INSERT INTO node (id, type, label, attrs, created_at)
        VALUES (:id, :type, :label, :attrs, :created_at)
        ON CONFLICT(id) DO UPDATE SET
            type = excluded.type,
            label = excluded.label,
            attrs = excluded.attrs
        """,
        {
            "id": id,
            "type": type,
            "label": label,
            "attrs": merged_attrs,
            "created_at": created_at,
        },
    )
    conn.commit()


def insert_edge(
    conn: sqlite3.Connection,
    *,
    id: str,
    src_id: str,
    dst_id: str,
    type: str,
    source_id: str | None,
    note: str | None = None,
) -> None:
    """Insert an edge row.

    This is the non-negotiable provenance constraint: ``source_id`` must be
    non-null and must reference an existing ``source`` row, or this raises
    ``sqlite3.IntegrityError``. Do not weaken this check.

    Args:
        conn: Open database connection.
        id: Stable identifier for the edge.
        src_id: Source node id.
        dst_id: Destination node id.
        type: Edge type; must be one of the CHECK-constrained values.
        source_id: Provenance source id. Must not be None.
        note: Optional free-text note recording which rule/evidence
            produced this edge (e.g. a protocol classifier's
            "keyword:modbus+port:502"). NULL for edge types that don't
            need it.

    Raises:
        sqlite3.IntegrityError: If ``source_id`` is None, does not exist in
            ``source``, or any other constraint (node FK, CHECK) fails.
    """
    conn.execute(
        """
        INSERT INTO edge (id, src_id, dst_id, type, source_id, note)
        VALUES (:id, :src_id, :dst_id, :type, :source_id, :note)
        ON CONFLICT(id) DO UPDATE SET
            src_id = excluded.src_id,
            dst_id = excluded.dst_id,
            type = excluded.type,
            source_id = excluded.source_id,
            note = excluded.note
        """,
        {
            "id": id,
            "src_id": src_id,
            "dst_id": dst_id,
            "type": type,
            "source_id": source_id,
            "note": note,
        },
    )
    conn.commit()


def count_nodes_by_type(conn: sqlite3.Connection) -> dict[str, int]:
    """Return a mapping of node type -> count."""
    rows = conn.execute(
        "SELECT type, COUNT(*) AS n FROM node GROUP BY type ORDER BY type"
    ).fetchall()
    return {row["type"]: row["n"] for row in rows}


def count_edges_by_type(conn: sqlite3.Connection) -> dict[str, int]:
    """Return a mapping of edge type -> count."""
    rows = conn.execute(
        "SELECT type, COUNT(*) AS n FROM edge GROUP BY type ORDER BY type"
    ).fetchall()
    return {row["type"]: row["n"] for row in rows}


def delete_edges_by_type(conn: sqlite3.Connection, type: str) -> int:
    """Delete every edge of the given type. Returns the number removed.

    Needed by re-runnable derived-edge enrichment passes (e.g. the
    protocol classifier's ``involves`` edges): ``insert_edge`` is
    upsert-by-id, so if a rule that used to match a CVE no longer does
    (a bug fix, a config change), the old edge row is never naturally
    removed just by re-running ``enrich.protocol.run()`` again -- it has
    to be explicitly cleared first. Not used for edges with real,
    independent per-run identity (e.g. ``describes``/``exploits``, which
    should accumulate history, not be wiped and rebuilt).
    """
    cur = conn.execute("DELETE FROM edge WHERE type = ?", (type,))
    conn.commit()
    return cur.rowcount


def source_exists(conn: sqlite3.Connection, source_id: str) -> bool:
    """Return True if ``source_id`` names an existing ``source`` row.

    Used by enrichment passes (e.g. ``enrich/protocol.py``) that want to
    check provenance availability before attempting an edge insert, so a
    missing source row can be logged/skipped clearly rather than surfacing
    only as a raw ``sqlite3.IntegrityError`` from the FK constraint.
    """
    row = conn.execute("SELECT 1 FROM source WHERE id = ?", (source_id,)).fetchone()
    return row is not None


def count_sources(conn: sqlite3.Connection) -> int:
    """Return the total number of source rows."""
    row = conn.execute("SELECT COUNT(*) AS n FROM source").fetchone()
    return int(row["n"])


def latest_fetch_times(conn: sqlite3.Connection) -> dict[str, str]:
    """Return a mapping of source name -> most recent fetched_at timestamp."""
    rows = conn.execute(
        """
        SELECT name, MAX(fetched_at) AS latest
        FROM source
        GROUP BY name
        ORDER BY name
        """
    ).fetchall()
    return {row["name"]: row["latest"] for row in rows}


def get_all_vuln_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of all CVE ids currently present as ``vuln`` nodes.

    Used by Week 2 collectors (NVD, EPSS) that enrich already-known CVEs
    rather than backfilling the full upstream universe.
    """
    rows = conn.execute("SELECT id FROM node WHERE type = 'vuln'").fetchall()
    return {row["id"] for row in rows}


def get_all_vuln_nodes(conn: sqlite3.Connection) -> list[dict]:
    """Return every ``vuln``-type node as a dict with parsed attrs.

    Used by ``enrich/protocol.py`` and ``enrich/timeline.py`` to read each
    CVE's merged-upsert attrs (description, nvd_published, date_added,
    etc.) without every caller re-implementing the JSON decode.

    Returns:
        A list of ``{"id": ..., "label": ..., "attrs": {...} | None}``
        dicts, one per ``vuln`` node.
    """
    rows = conn.execute(
        "SELECT id, label, attrs FROM node WHERE type = 'vuln' ORDER BY id"
    ).fetchall()
    vulns: list[dict] = []
    for row in rows:
        attrs = None
        if row["attrs"] is not None:
            try:
                attrs = json.loads(row["attrs"])
            except json.JSONDecodeError:
                attrs = None
        vulns.append({"id": row["id"], "label": row["label"], "attrs": attrs})
    return vulns


def get_all_products(conn: sqlite3.Connection) -> list[dict]:
    """Return every ``product``-type node as a dict with parsed attrs.

    Used by ``enrich/purdue.py`` to join each product's vendor/product
    attrs against ``config/purdue_map.yaml``.

    Returns:
        A list of ``{"id": ..., "label": ..., "attrs": {...} | None}``
        dicts, one per ``product`` node. ``attrs`` is decoded from JSON;
        nodes with no/invalid attrs JSON get ``None``.
    """
    rows = conn.execute(
        "SELECT id, label, attrs FROM node WHERE type = 'product' ORDER BY id"
    ).fetchall()
    products: list[dict] = []
    for row in rows:
        attrs = None
        if row["attrs"] is not None:
            try:
                attrs = json.loads(row["attrs"])
            except json.JSONDecodeError:
                attrs = None
        products.append({"id": row["id"], "label": row["label"], "attrs": attrs})
    return products


def get_all_group_nodes(conn: sqlite3.Connection) -> list[dict]:
    """Return every ``group``-type node as a dict with parsed attrs.

    Used by the Streamlit UI's Threat Groups page (``ui/data.py``) to
    populate the group picker without duplicating this query per caller.

    Returns:
        A list of ``{"id": ..., "label": ..., "attrs": {...} | None}``
        dicts, one per ``group`` node, ordered by id.
    """
    rows = conn.execute(
        "SELECT id, label, attrs FROM node WHERE type = 'group' ORDER BY id"
    ).fetchall()
    groups: list[dict] = []
    for row in rows:
        attrs = None
        if row["attrs"] is not None:
            try:
                attrs = json.loads(row["attrs"])
            except json.JSONDecodeError:
                attrs = None
        groups.append({"id": row["id"], "label": row["label"], "attrs": attrs})
    return groups


def get_outgoing_edges(
    conn: sqlite3.Connection, src_id: str, edge_types: list[str] | None = None
) -> list[dict]:
    """Return every edge whose ``src_id`` matches, joined with the
    destination node's type/label, optionally filtered by edge type.

    Used by the Streamlit UI (Threat Groups page) to render a group's
    exploits/tools/techniques/handoffs with each row's destination and
    provenance, without hand-rolling the join per page. Parameterized
    throughout -- ``edge_types``, if given, is bound via placeholders,
    never string-interpolated.

    Args:
        conn: Open database connection.
        src_id: The source node id (e.g. a group id).
        edge_types: Optional list of edge types to restrict to. ``None``
            returns every outgoing edge regardless of type.

    Returns:
        A list of dicts: ``edge_id``, ``type``, ``dst_id``, ``dst_type``,
        ``dst_label``, ``source_id``, ``note``.
    """
    query = (
        "SELECT e.id AS edge_id, e.type AS type, e.dst_id AS dst_id, "
        "n.type AS dst_type, n.label AS dst_label, e.source_id AS source_id, "
        "e.note AS note "
        "FROM edge e JOIN node n ON n.id = e.dst_id "
        "WHERE e.src_id = ?"
    )
    params: list[str] = [src_id]
    if edge_types:
        placeholders = ",".join("?" for _ in edge_types)
        query += f" AND e.type IN ({placeholders})"
        params.extend(edge_types)
    query += " ORDER BY e.type, e.dst_id"

    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_incoming_edges(
    conn: sqlite3.Connection, dst_id: str, edge_types: list[str] | None = None
) -> list[dict]:
    """Return every edge whose ``dst_id`` matches, joined with the source
    node's type/label, optionally filtered by edge type.

    The mirror of ``get_outgoing_edges`` -- used by the Threat Groups page
    to show handoffs *received* by a group (e.g. voltzite receiving from
    sylvanite), which are declared on the sender's corpus file, not the
    receiver's.

    Args:
        conn: Open database connection.
        dst_id: The destination node id (e.g. a group id).
        edge_types: Optional list of edge types to restrict to.

    Returns:
        A list of dicts: ``edge_id``, ``type``, ``src_id``, ``src_type``,
        ``src_label``, ``source_id``, ``note``.
    """
    query = (
        "SELECT e.id AS edge_id, e.type AS type, e.src_id AS src_id, "
        "n.type AS src_type, n.label AS src_label, e.source_id AS source_id, "
        "e.note AS note "
        "FROM edge e JOIN node n ON n.id = e.src_id "
        "WHERE e.dst_id = ?"
    )
    params: list[str] = [dst_id]
    if edge_types:
        placeholders = ",".join("?" for _ in edge_types)
        query += f" AND e.type IN ({placeholders})"
        params.extend(edge_types)
    query += " ORDER BY e.type, e.src_id"

    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_source(conn: sqlite3.Connection, source_id: str) -> dict | None:
    """Return one ``source`` row as a dict, or None if it does not exist.

    Used by ``ui/components/source_footer.py`` to render provenance
    (name/url/fetched_at) for any displayed claim, given its ``source_id``.
    """
    row = conn.execute(
        "SELECT id, name, url, fetched_at, sha256, http_status FROM source WHERE id = ?",
        (source_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def insert_signal(
    conn: sqlite3.Connection,
    *,
    id: str,
    cve: str,
    source: str,
    signal_type: str,
    ref: str | None,
    observed_at: str,
    meta: str | None,
    source_id: str,
) -> None:
    """Insert or update a weaponization-timing signal row (upsert by id).

    Args:
        conn: Open database connection.
        id: Stable identifier for the signal row.
        cve: CVE id the signal refers to (plain text, no FK to node.id).
        source: One of 'poc-github', 'exploitdb', 'nuclei', 'metasploit'.
        signal_type: Free-text signal kind, e.g. 'poc_repo_created'.
        ref: A URL or other reference for the signal, if any.
        observed_at: ISO-8601 (or date) timestamp of the observed event.
        meta: Opaque JSON-encoded extra metadata, or None.
        source_id: Provenance source id. Must not be None.

    Raises:
        sqlite3.IntegrityError: If ``source_id`` does not reference an
            existing ``source`` row, or any other constraint fails.
    """
    conn.execute(
        """
        INSERT INTO signal (id, cve, source, signal_type, ref, observed_at, meta, source_id)
        VALUES (:id, :cve, :source, :signal_type, :ref, :observed_at, :meta, :source_id)
        ON CONFLICT(id) DO UPDATE SET
            cve = excluded.cve,
            source = excluded.source,
            signal_type = excluded.signal_type,
            ref = excluded.ref,
            observed_at = excluded.observed_at,
            meta = excluded.meta,
            source_id = excluded.source_id
        """,
        {
            "id": id,
            "cve": cve,
            "source": source,
            "signal_type": signal_type,
            "ref": ref,
            "observed_at": observed_at,
            "meta": meta,
            "source_id": source_id,
        },
    )
    conn.commit()


def count_signals_by_source(conn: sqlite3.Connection) -> dict[str, int]:
    """Return a mapping of signal source -> count."""
    rows = conn.execute(
        "SELECT source, COUNT(*) AS n FROM signal GROUP BY source ORDER BY source"
    ).fetchall()
    return {row["source"]: row["n"] for row in rows}


def insert_metric_observation(
    conn: sqlite3.Connection,
    *,
    id: str,
    node_id: str,
    metric_name: str,
    value: float,
    model_version: str | None,
    observed_at: str,
    source_id: str,
) -> None:
    """Insert or update a metric observation row (upsert by id).

    Column names match the Week 1 schema exactly (``metric_name``, not the
    engineering spec's illustrative ``metric``; ``node_id``, not ``cve``) --
    see ``model/schema.sql``.

    Args:
        conn: Open database connection.
        id: Stable identifier for the observation row.
        node_id: Node id the observation is about (e.g. a CVE id).
        metric_name: e.g. 'epss', 'epss_percentile', 'cvss_v31_base'.
        value: The observed numeric value.
        model_version: Model/scoring generation, if applicable (e.g. an
            EPSS model version or CVSS version string).
        observed_at: ISO-8601 (or date) timestamp the value was published.
        source_id: Provenance source id. Must not be None.

    Raises:
        sqlite3.IntegrityError: If ``source_id``/``node_id`` do not
            reference existing rows, or any other constraint fails.
    """
    conn.execute(
        """
        INSERT INTO metric_observation
            (id, node_id, metric_name, value, model_version, observed_at, source_id)
        VALUES
            (:id, :node_id, :metric_name, :value, :model_version, :observed_at, :source_id)
        ON CONFLICT(id) DO UPDATE SET
            node_id = excluded.node_id,
            metric_name = excluded.metric_name,
            value = excluded.value,
            model_version = excluded.model_version,
            observed_at = excluded.observed_at,
            source_id = excluded.source_id
        """,
        {
            "id": id,
            "node_id": node_id,
            "metric_name": metric_name,
            "value": value,
            "model_version": model_version,
            "observed_at": observed_at,
            "source_id": source_id,
        },
    )
    conn.commit()


def count_metric_observations_by_name(conn: sqlite3.Connection) -> dict[str, int]:
    """Return a mapping of metric_name -> count."""
    rows = conn.execute(
        "SELECT metric_name, COUNT(*) AS n FROM metric_observation GROUP BY metric_name "
        "ORDER BY metric_name"
    ).fetchall()
    return {row["metric_name"]: row["n"] for row in rows}


def delete_metric_observations_by_names(conn: sqlite3.Connection, metric_names: list[str]) -> int:
    """Delete every metric_observation row whose metric_name is in the given list.

    Returns the number removed. Needed by the same re-runnability concern
    as ``delete_edges_by_type``: ``insert_metric_observation`` is
    upsert-by-id, so a metric that becomes uncomputable on a later run
    (e.g. the input signal/advisory row it depended on was corrected or
    removed) is never naturally cleared -- the previous run's stale value
    sits in the table forever unless explicitly deleted first. A derived-
    metrics enrichment pass should clear its own metric names here before
    recomputing, mirroring ``enrich.protocol.run()``'s
    ``delete_edges_by_type("involves")`` call.
    """
    if not metric_names:
        return 0
    placeholders = ",".join("?" for _ in metric_names)
    cur = conn.execute(
        f"DELETE FROM metric_observation WHERE metric_name IN ({placeholders})",
        metric_names,
    )
    conn.commit()
    return cur.rowcount
