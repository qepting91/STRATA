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

`NVD_API_KEY` is read from the environment only, via `pydantic-settings`,
optionally sourced from a local `.env` file. `.env` is listed in
`.gitignore` and must never be committed. `.env.example` documents the
expected variable name with an empty value.

`Settings.nvd_api_key` is typed as `pydantic.SecretStr`, not a plain
`str`, so a stray `repr(settings)`/log line masks it rather than printing
the raw value; the one call site that needs the real value
(`collect/nvd.py`, via `cli.py`) unwraps it explicitly with
`get_secret_value()`. The key is sent to NVD as a request header
(`apiKey`) via `NetClient.fetch()`'s `extra_headers` parameter, which is
merged into the outbound request only — it is never part of the
cache/manifest key, never written into `manifest.json` or the `source`
table's `url` column, and never appears in an exception message (only
`host`, never a full URL with credentials, is ever interpolated into
`EgressDenied`). This was specifically reviewed: an earlier draft of the
NVD collector loaded the key but never actually sent it (the collector
had no way to pass a header through `net.py` at all), which a security
review caught before it was fixed — worth noting here since the
easy-but-wrong fix would have been appending `&apiKey=...` to the URL
string, which *would* have leaked into the manifest and the `source`
table.

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

**Rate-limit overrides (Week 3):** `NetClient` accepts an optional
`rate_limit_overrides` dict, merged on top of the file-loaded config, so
a caller who knows a faster tier legitimately applies (NVD's documented
50 req/30s tier when `NVD_API_KEY` is present) can raise the effective
limit without editing `config/sources.toml` — which has no way to
express "conditional on a secret being present." This is opt-in per
collector construction, not a general bypass: only `cli.py`'s NVD
collector wiring passes an override, and only when the key is actually
set. A bounded 429 retry (3 attempts, exponential backoff, honoring
`Retry-After`) was added to `net.py` after NVD's real short-burst limit
was hit live in testing, even with the override applied and a valid key
— it always terminates (bounded loop, no infinite retry) and never
retries a non-429 response.

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

