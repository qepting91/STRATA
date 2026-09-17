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

    return conn


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

    Raises:
        sqlite3.IntegrityError: If ``source_id`` is None, does not exist in
            ``source``, or any other constraint (node FK, CHECK) fails.
    """
    conn.execute(
        """
        INSERT INTO edge (id, src_id, dst_id, type, source_id)
        VALUES (:id, :src_id, :dst_id, :type, :source_id)
        ON CONFLICT(id) DO UPDATE SET
            src_id = excluded.src_id,
            dst_id = excluded.dst_id,
            type = excluded.type,
            source_id = excluded.source_id
        """,
        {
            "id": id,
            "src_id": src_id,
            "dst_id": dst_id,
            "type": type,
            "source_id": source_id,
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
