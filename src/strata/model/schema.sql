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
    source_id TEXT NOT NULL REFERENCES source(id),
    -- Week 3 addition: records which rule fired for a classifier-derived
    -- edge (e.g. involves edges from enrich/protocol.py: "keyword:modbus").
    -- NULL for every other edge type, which is unaffected. See store.py's
    -- get_connection() for the runtime migration that adds this column to
    -- any pre-existing (Week 1/2) database that predates this change.
    note      TEXT
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

-- Week 2 addition: weaponization-timing signals (PoC-in-GitHub, Exploit-DB,
-- Nuclei, Metasploit). Deliberately NOT part of the node/edge graph -- a
-- signal is a raw "this CVE was referenced here, on this date" fact, not an
-- entity. `cve` is a plain text column (no FK to node.id): a signal can be
-- recorded for a CVE the local graph has not ingested as a vuln node yet.
-- Still carries the same non-negotiable provenance FK into `source`.
CREATE TABLE IF NOT EXISTS signal (
    id          TEXT PRIMARY KEY,
    cve         TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (
        source IN ('poc-github', 'exploitdb', 'nuclei', 'metasploit')
    ),
    signal_type TEXT NOT NULL,
    ref         TEXT,
    observed_at TEXT NOT NULL,
    meta        TEXT,
    source_id   TEXT NOT NULL REFERENCES source(id)
);

CREATE INDEX IF NOT EXISTS idx_signal_cve ON signal(cve);
CREATE INDEX IF NOT EXISTS idx_signal_source ON signal(source);
