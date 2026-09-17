"""Egress-guarded, rate-limited, caching HTTP client for STRATA collectors.

Security model (see SECURITY.md):

- Every outbound request is checked against a static hostname allowlist
  (config/allowlist.txt) before the socket opens. Off-allowlist hosts
  raise EgressDenied.
- follow_redirects=False is deliberate: a redirect is an allowlist
  bypass vector. Any 3xx response is treated as blocked, never silently
  followed or handed back to the caller as if it were content.
- Conditional requests (If-None-Match / If-Modified-Since) avoid
  refetching unchanged resources; a matching 304 reuses the cached
  snapshot.
- offline=True short-circuits to the on-disk cache with zero network
  calls; a cache miss raises OfflineCacheMiss.
- Every 200 response is snapshotted to
  data/raw/<source>/<date>/<sha256[:20]>.json (date = YYYY-MM-DD, no
  colons, for Windows path safety) with a sidecar manifest.json mapping
  URL -> {etag, last_modified, sha256, snapshot_path}.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

USER_AGENT = "strata-collector/0.1 (+https://github.com/local/strata; contact: local-dev)"

# `source` names become directory components under data/raw/. Collectors
# only ever pass hardcoded literals today, but fetch() is a public method,
# so this is enforced defensively rather than trusted implicitly -- a
# future source name that includes "../" must not be able to escape
# data/raw/.
_SOURCE_NAME_RE = re.compile(r"^[a-z0-9_-]+$")


def _validate_source_name(source: str) -> None:
    if not _SOURCE_NAME_RE.match(source):
        raise ValueError(
            f"invalid source name {source!r}: must match {_SOURCE_NAME_RE.pattern}"
        )

# Truncate sha256 to this many hex chars in snapshot filenames only (the
# full digest is always retained in the manifest and in FetchResult). This
# keeps paths short under a long OneDrive-synced working directory on
# Windows, where full paths can otherwise exceed MAX_PATH.
SNAPSHOT_HASH_LEN = 20


class EgressDenied(Exception):
    """Raised when a request targets a host not on the allowlist, or when
    a redirect response would escape the allowlist."""


class OfflineCacheMiss(Exception):
    """Raised in offline mode when no cached snapshot exists for a URL."""


@dataclass
class FetchResult:
    """The result of a single net.fetch() call."""

    content: bytes
    sha256: str
    from_cache: bool
    etag: str | None
    url: str
    status_code: int | None = None


def load_allowlist(path: Path | str = "config/allowlist.txt") -> set[str]:
    """Load the set of permitted egress hostnames.

    Args:
        path: Path to a plain-text file, one hostname per line. Blank
            lines and lines starting with # are ignored.

    Returns:
        Set of lowercased hostnames.
    """
    p = Path(path)
    if not p.exists():
        return set()
    hosts: set[str] = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hosts.add(line.lower())
    return hosts


def load_rate_limits(
    path: Path | str = "config/sources.toml",
) -> dict[str, tuple[int, float]]:
    """Load per-host rate limit config: host -> (max_requests, window_seconds)."""
    p = Path(path)
    if not p.exists():
        return {}
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    limits: dict[str, tuple[int, float]] = {}
    for host, cfg in data.get("hosts", {}).items():
        limits[host.lower()] = (
            int(cfg.get("max_requests", 1)),
            float(cfg.get("window_seconds", 1.0)),
        )
    return limits


class _RateLimiter:
    """A simple sleep-based per-host token bucket.

    Not thread-safe by design -- STRATA collectors run single-process,
    single-threaded fetch loops.
    """

    def __init__(self, limits: dict[str, tuple[int, float]]) -> None:
        self._limits = limits
        self._last_request_at: dict[str, float] = {}

    def wait(self, host: str) -> None:
        host = host.lower()
        if host not in self._limits:
            return
        max_requests, window_seconds = self._limits[host]
        if max_requests <= 0:
            return
        min_interval = window_seconds / max_requests
        last = self._last_request_at.get(host)
        now = time.monotonic()
        if last is not None:
            elapsed = now - last
            remaining = min_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self._last_request_at[host] = time.monotonic()


class _Manifest:
    """On-disk manifest of URL -> cached snapshot metadata for one source."""

    def __init__(self, source: str, data_dir: Path) -> None:
        _validate_source_name(source)
        self._path = data_dir / "raw" / source / "manifest.json"
        self._data: dict[str, dict] = {}
        if self._path.exists():
            self._data = json.loads(self._path.read_text(encoding="utf-8"))

    def get(self, url: str) -> dict | None:
        return self._data.get(url)

    def set(self, url: str, entry: dict) -> None:
        self._data[url] = entry
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8")


def _snapshot_path(data_dir: Path, source: str, sha256: str) -> Path:
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    short_hash = sha256[:SNAPSHOT_HASH_LEN]
    return data_dir / "raw" / source / date_str / f"{short_hash}.json"


class NetClient:
    """Egress-guarded HTTP client with caching and rate limiting.

    Instantiate one per collection run (or reuse across a process). Not
    safe to share across threads.
    """

    def __init__(
        self,
        allowlist_path: Path | str = "config/allowlist.txt",
        sources_config_path: Path | str = "config/sources.toml",
        data_dir: Path | str = "data",
    ) -> None:
        self._allowlist = load_allowlist(allowlist_path)
        self._rate_limiter = _RateLimiter(load_rate_limits(sources_config_path))
        self._data_dir = Path(data_dir)
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=30.0,
            headers={"User-Agent": USER_AGENT},
            event_hooks={"request": [self._check_allowlist]},
        )

    def _check_allowlist(self, request: httpx.Request) -> None:
        host = request.url.host
        if host not in self._allowlist:
            raise EgressDenied(f"{host} is not in the egress allowlist")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> NetClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def fetch(self, url: str, source: str, offline: bool = False) -> FetchResult:
        """Fetch a URL, honoring the allowlist, cache, and offline mode.

        Args:
            url: Fully-qualified URL to fetch. Host must be on the
                allowlist unless served entirely from cache in offline
                mode.
            source: Logical source name (e.g. cisa-kev), used as the
                cache subdirectory and manifest key.
            offline: If True, never touch the network -- serve from the
                on-disk manifest/cache only, raising OfflineCacheMiss
                if nothing is cached for this URL.

        Returns:
            A FetchResult with the response content (or cached content).

        Raises:
            EgressDenied: If the URL host is not on the allowlist (only
                possible when offline=False), or a redirect response is
                received.
            OfflineCacheMiss: If offline=True and no cached entry exists
                for this URL.
        """
        manifest = _Manifest(source, self._data_dir)
        cached = manifest.get(url)

        if offline:
            if cached is None:
                raise OfflineCacheMiss(f"No cached snapshot for {url!r} (source={source!r})")
            snapshot_path = Path(cached["snapshot_path"])
            content = snapshot_path.read_bytes()
            return FetchResult(
                content=content,
                sha256=cached["sha256"],
                from_cache=True,
                etag=cached.get("etag"),
                url=url,
                status_code=None,
            )

        host = httpx.URL(url).host
        if host not in self._allowlist:
            raise EgressDenied(f"{host} is not in the egress allowlist")

        headers: dict[str, str] = {}
        if cached is not None:
            if cached.get("etag"):
                headers["If-None-Match"] = cached["etag"]
            if cached.get("last_modified"):
                headers["If-Modified-Since"] = cached["last_modified"]

        self._rate_limiter.wait(host)
        response = self._client.get(url, headers=headers)

        if response.status_code == 304:
            if cached is None:
                raise OfflineCacheMiss(
                    f"Received 304 for {url!r} but no cached snapshot exists"
                )
            snapshot_path = Path(cached["snapshot_path"])
            content = snapshot_path.read_bytes()
            return FetchResult(
                content=content,
                sha256=cached["sha256"],
                from_cache=True,
                etag=cached.get("etag"),
                url=url,
                status_code=304,
            )

        if response.is_redirect or 300 <= response.status_code < 400:
            raise EgressDenied(
                f"Redirect response ({response.status_code}) from {host} blocked; "
                "redirects are not followed"
            )

        response.raise_for_status()

        content = response.content
        sha256 = hashlib.sha256(content).hexdigest()
        snapshot_path = _snapshot_path(self._data_dir, source, sha256)
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_bytes(content)

        etag = response.headers.get("etag")
        last_modified = response.headers.get("last-modified")
        manifest.set(
            url,
            {
                "etag": etag,
                "last_modified": last_modified,
                "sha256": sha256,
                "snapshot_path": str(snapshot_path),
            },
        )

        return FetchResult(
            content=content,
            sha256=sha256,
            from_cache=False,
            etag=etag,
            url=url,
            status_code=response.status_code,
        )
