-- STRATA graph schema (Week 1)
-- Provenance rule (non-negotiable): every edge row requires a non-null
-- source_id FK into `source`. This is enforced both by NOT NULL + FK here,
-- and by the DAO layer in store.py raising sqlite3.IntegrityError on
-- violation (missing source_id or a source_id that does not exist).

CREATE TABLE IF NOT EXISTS source (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    url         TEXT,
    fetched_at  TEXT NOT NULL,
    sha256      TEXT,
    http_status INTEGER
);

CREATE TABLE IF NOT EXISTS node (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL CHECK (
        type IN (
            'group', 'alias', 'campaign', 'technique', 'vuln', 'product',
            'vendor', 'tool', 'protocol', 'sector', 'geo', 'advisory',
            'source'
        )
    ),
    label      TEXT NOT NULL,
    attrs      TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS edge (
    id        TEXT PRIMARY KEY,
    src_id    TEXT NOT NULL REFERENCES node(id),
    dst_id    TEXT NOT NULL REFERENCES node(id),
    type      TEXT NOT NULL CHECK (
        type IN (
            'uses', 'exploits', 'targets', 'implements', 'hands_off_to',
            'overlaps_with', 'affects', 'involves', 'made_by', 'describes'
        )
    ),
    source_id TEXT NOT NULL REFERENCES source(id)
);

-- Unused this week; schema present so it is stable across future weeks.
CREATE TABLE IF NOT EXISTS metric_observation (
    id            TEXT PRIMARY KEY,
    node_id       TEXT NOT NULL REFERENCES node(id),
    metric_name   TEXT NOT NULL,
    value         REAL NOT NULL,
    model_version TEXT,
    observed_at   TEXT NOT NULL,
    source_id     TEXT NOT NULL REFERENCES source(id)
);

CREATE INDEX IF NOT EXISTS idx_edge_src ON edge(src_id);
CREATE INDEX IF NOT EXISTS idx_edge_dst ON edge(dst_id);
CREATE INDEX IF NOT EXISTS idx_edge_source ON edge(source_id);
CREATE INDEX IF NOT EXISTS idx_metric_node ON metric_observation(node_id);
