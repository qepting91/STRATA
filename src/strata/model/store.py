"""SQLite data-access layer for the STRATA graph.

Enforces the project's non-negotiable provenance rule: every edge row must
carry a non-null ``source_id`` that resolves to an existing row in
``source``. This is enforced at the schema level (NOT NULL + FOREIGN KEY,
with ``PRAGMA foreign_keys=ON``) and exercised in ``tests/test_store.py``.
"""

from __future__ import annotations

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

    Args:
        conn: Open database connection.
        id: Stable natural or synthetic identifier for the node.
        type: Node type; must be one of the CHECK-constrained values.
        label: Human-readable label.
        attrs: Opaque JSON-encoded attribute blob, or None.
        created_at: ISO-8601 timestamp of first observation.
    """
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
            "attrs": attrs,
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
