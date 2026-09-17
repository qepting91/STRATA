# Security posture

STRATA is a security portfolio artifact; its own security posture is part
of the demo. This document describes the threat model for the tool
itself (not for the OT/ICS systems it studies).

## Egress control

`src/strata/net.py` wraps `httpx` with a static hostname allowlist loaded
from `config/allowlist.txt` (currently `www.cisa.gov`, `api.github.com`,
`raw.githubusercontent.com`). Every outbound request is checked against
this list in an `httpx` request event hook, before the socket opens. A
request to any other host raises `EgressDenied` and is never sent.

`httpx.Client(follow_redirects=False, ...)` is deliberate: a redirect is
an allowlist bypass vector — a response from an allowlisted host could
otherwise redirect to an arbitrary off-allowlist host and be followed
transparently. Any 3xx response (except a conditional-request `304`,
which is handled explicitly and is not a redirect) is treated as blocked:
`net.py` raises `EgressDenied` rather than silently following it or
returning it to the caller as if it were content. This is exercised in
`tests/test_net.py`.

### Residual risk: hostname allowlist is not IP-pinned

The allowlist check inspects `request.url.host` (the literal hostname
string); it does not resolve DNS itself or pin the connection to a known
IP. DNS resolution happens downstream, inside `httpx`/`httpcore`. If DNS
for one of the three allowlisted hosts were ever compromised (cache
poisoning, a hijacked resolver, or a compromised registrar), the
hostname check would still pass while the TCP connection reached an
attacker-chosen address — including a private/link-local one. This
requires a DNS-layer compromise, not just a malicious response from
CISA/GitHub, so it's accepted as a documented residual risk rather than
mitigated this week. A future hardening step would resolve the hostname
first, reject private/link-local/loopback resolved addresses, and
connect to the pinned IP with the original Host/SNI.

`net.py` also validates that `source` (the cache subdirectory name)
matches `^[a-z0-9_-]+$` before it is used to build any filesystem path,
so a future collector that ever derives `source` from external/config
data cannot use it as a path-traversal vector into `data/raw/`.

## No eval, no pickle (project-wide policy)

Not exercised by Week 1 code (there is no YAML, hunt expression, or
untrusted-code evaluation path yet), but stated here as the standing
project policy for all future weeks: no `pickle` anywhere in the
pipeline; any future YAML loading uses `yaml.safe_load`, never
`yaml.load`; the future hunt runner's `falsifies_if` expressions will be
evaluated through a restricted AST evaluator (`simpleeval`) over a fixed
variable namespace, never Python `eval`. All ingest in this pipeline is
JSON, CSV, or plain text — never a binary/executable payload.

## Secrets handling

`NVD_API_KEY` (reserved for the Week 2 NVD collector; unused this week)
is read from the environment only, via `pydantic-settings`, optionally
sourced from a local `.env` file. `.env` is listed in `.gitignore` and
must never be committed. `.env.example` documents the expected variable
name with an empty value.

## Supply chain

`uv.lock` is committed with hash-pinned dependency versions. Runtime
dependencies are deliberately minimal this week: `httpx`, `pydantic`,
`pydantic-settings`, `typer`. `ruff` runs as a lint gate; `pytest` is the
test runner. (`pip-audit` is not wired into CI yet — later-week scope.)

## Rate limiting and courtesy

`net.py` applies a simple per-host, sleep-based rate limiter configured
from `config/sources.toml` (host -> max_requests/window_seconds), with
conservative 1 req/sec defaults for all three Week 1 hosts. All requests
carry an identifying `User-Agent` string. Conditional requests
(`If-None-Match` / `If-Modified-Since`) avoid re-fetching unchanged
resources, backed by a per-source on-disk manifest.

## Reproducibility as an integrity control

Every successful (200) fetch is written to
`data/raw/<source>/<ISO-date>/<sha256[:20]>.json`, with a sidecar
`manifest.json` recording the URL, ETag/Last-Modified, full SHA-256, and
snapshot path. `--offline` replays the entire collection run from this
cache with zero network calls; any node/edge in the database is
re-derivable from the snapshot set.

Filenames truncate the SHA-256 to the first 20 hex characters purely to
keep paths short (the full 64-character digest is always retained in the
manifest and in the in-memory `FetchResult`). This is a Windows/OneDrive
path-length mitigation (see below), not a reduction in integrity
guarantees — collisions in the first 20 hex chars of SHA-256 are not a
practical concern at this corpus size, and the full hash is always
available for verification.

## Known caveat: SQLite WAL under OneDrive sync

`model/store.py` opens the database with `PRAGMA journal_mode=WAL`, which
creates `-wal` and `-shm` sidecar files alongside `strata.db`. This
working directory lives under OneDrive, whose background sync process
can race a WAL checkpoint or the creation/deletion of these sidecar
files, particularly on Windows. In practice this is not blocking for
Week 1: STRATA runs single-process, single-writer, and OneDrive's file
locking behavior tolerates the short-lived WAL/SHM files that
single-process dev traffic produces. If this becomes a problem in a
later week (e.g. running the CLI and the future Streamlit UI
concurrently), the mitigation is to move `data/` outside the
OneDrive-synced tree, or pause sync during active development sessions.

## Containerized run

Not implemented this week. The engineering spec's `docker-compose.yml`
sketch (read-only root filesystem, `cap_drop: [ALL]`,
`no-new-privileges`, no published ports, `data/` as the only writable
volume) is later-week scope; see `strata-engineering-spec.md` §9.

