"""Tests for strata.net — the egress-guarded, caching HTTP client.

All network interaction is mocked via respx; no real network calls happen
in this test module.
"""

from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
import respx

from strata import net


@pytest.fixture
def net_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("example.test\n", encoding="utf-8")

    sources_path = tmp_path / "sources.toml"
    sources_path.write_text(
        '[hosts."example.test"]\nmax_requests = 1000\nwindow_seconds = 1.0\n',
        encoding="utf-8",
    )

    data_dir = tmp_path / "data"
    return allowlist_path, sources_path, data_dir


@pytest.fixture
def client(net_paths: tuple[Path, Path, Path]) -> net.NetClient:
    allowlist_path, sources_path, data_dir = net_paths
    c = net.NetClient(
        allowlist_path=allowlist_path,
        sources_config_path=sources_path,
        data_dir=data_dir,
    )
    yield c
    c.close()


@respx.mock
def test_allowlisted_200_writes_snapshot_and_manifest(
    client: net.NetClient, net_paths: tuple[Path, Path, Path]
) -> None:
    _, _, data_dir = net_paths
    url = "https://example.test/feed.json"
    route = respx.get(url).mock(return_value=httpx.Response(200, json={"hello": "world"}))

    result = client.fetch(url, source="unit-test", offline=False)

    assert route.called
    assert result.from_cache is False
    assert result.content == b'{"hello":"world"}' or b"hello" in result.content

    manifest_path = data_dir / "raw" / "unit-test" / "manifest.json"
    assert manifest_path.exists()

    snapshot_files = list((data_dir / "raw" / "unit-test").rglob("*.json"))
    # manifest.json plus at least one dated snapshot file
    assert any(p.name != "manifest.json" for p in snapshot_files)


@respx.mock
def test_off_allowlist_host_raises_egress_denied(
    client: net.NetClient, net_paths: tuple[Path, Path, Path]
) -> None:
    _, _, data_dir = net_paths
    url = "https://not-allowed.test/feed.json"
    respx.get(url).mock(return_value=httpx.Response(200, json={"hello": "world"}))

    with pytest.raises(net.EgressDenied):
        client.fetch(url, source="unit-test", offline=False)

    raw_dir = data_dir / "raw" / "unit-test"
    assert not raw_dir.exists() or not any(raw_dir.rglob("*.json"))


@respx.mock
def test_redirect_from_allowlisted_host_is_blocked_not_followed(
    client: net.NetClient, net_paths: tuple[Path, Path, Path]
) -> None:
    _, _, data_dir = net_paths
    url = "https://example.test/redirecting"
    respx.get(url).mock(
        return_value=httpx.Response(302, headers={"Location": "https://not-allowed.test/x"})
    )

    with pytest.raises(net.EgressDenied):
        client.fetch(url, source="unit-test", offline=False)

    raw_dir = data_dir / "raw" / "unit-test"
    assert not raw_dir.exists() or not any(raw_dir.rglob("*.json"))


@respx.mock
def test_conditional_request_304_reuses_cached_snapshot(
    client: net.NetClient, net_paths: tuple[Path, Path, Path]
) -> None:
    url = "https://example.test/feed.json"

    first_route = respx.get(url).mock(
        return_value=httpx.Response(
            200, json={"v": 1}, headers={"ETag": '"abc123"'}
        )
    )
    first = client.fetch(url, source="unit-test", offline=False)
    assert first.from_cache is False
    assert first_route.called

    # Second request should send If-None-Match and get a 304 back.
    respx.get(url).mock(return_value=httpx.Response(304))
    second = client.fetch(url, source="unit-test", offline=False)

    assert second.from_cache is True
    assert second.content == first.content


@respx.mock
def test_offline_with_cache_returns_cached_and_makes_zero_network_calls(
    client: net.NetClient, net_paths: tuple[Path, Path, Path]
) -> None:
    url = "https://example.test/feed.json"
    route = respx.get(url).mock(return_value=httpx.Response(200, json={"v": 1}))

    # Populate the cache with a normal online fetch first.
    online_result = client.fetch(url, source="unit-test", offline=False)
    assert route.call_count == 1

    # Reset the route's call count tracking by asserting no further calls
    # happen during the offline fetch below.
    calls_before = route.call_count
    offline_result = client.fetch(url, source="unit-test", offline=True)

    assert route.call_count == calls_before  # zero additional network calls
    assert offline_result.from_cache is True
    assert offline_result.content == online_result.content


def test_offline_without_cache_raises_clear_error(
    net_paths: tuple[Path, Path, Path]
) -> None:
    allowlist_path, sources_path, data_dir = net_paths
    client = net.NetClient(
        allowlist_path=allowlist_path,
        sources_config_path=sources_path,
        data_dir=data_dir,
    )
    try:
        with pytest.raises(net.OfflineCacheMiss):
            client.fetch(
                "https://example.test/never-fetched.json",
                source="unit-test",
                offline=True,
            )
    finally:
        client.close()


def test_client_never_follows_redirects_by_config(client: net.NetClient) -> None:
    """Regression guard: the redirect-blocking design in fetch() only holds
    because the underlying httpx.Client is built with follow_redirects=False.
    If a future refactor flips this (or constructs a second client that
    doesn't), the allowlist hook's single-shot assumption silently breaks."""
    assert client._client.follow_redirects is False


@pytest.mark.parametrize("bad_source", ["../escape", "a/b", "a b", "UPPER", ""])
def test_fetch_rejects_unsafe_source_names(
    client: net.NetClient, bad_source: str
) -> None:
    with pytest.raises(ValueError):
        client.fetch("https://example.test/feed.json", source=bad_source, offline=True)


def test_rate_limit_override_wins_over_file_config(
    net_paths: tuple[Path, Path, Path],
) -> None:
    """A rate_limit_overrides entry must replace, not merge alongside, the
    file-loaded limit for that host -- this is what lets cli.py raise NVD's
    effective rate limit when an API key is present without editing
    config/sources.toml (which has no way to express "conditional on a
    secret")."""
    allowlist_path, sources_path, data_dir = net_paths
    # File config says 1000 req/1s for example.test (see net_paths fixture).
    client = net.NetClient(
        allowlist_path=allowlist_path,
        sources_config_path=sources_path,
        data_dir=data_dir,
        rate_limit_overrides={"example.test": (1, 60.0)},
    )
    try:
        assert client._rate_limiter._limits["example.test"] == (1, 60.0)
    finally:
        client.close()


def test_rate_limit_override_for_unconfigured_host_is_added(
    net_paths: tuple[Path, Path, Path],
) -> None:
    allowlist_path, sources_path, data_dir = net_paths
    client = net.NetClient(
        allowlist_path=allowlist_path,
        sources_config_path=sources_path,
        data_dir=data_dir,
        rate_limit_overrides={"services.nvd.nist.gov": (50, 30.0)},
    )
    try:
        assert client._rate_limiter._limits["services.nvd.nist.gov"] == (50, 30.0)
        # File-loaded host config for example.test is untouched.
        assert client._rate_limiter._limits["example.test"] == (1000, 1.0)
    finally:
        client.close()


@respx.mock
def test_429_is_retried_with_backoff_then_succeeds(
    client: net.NetClient,
) -> None:
    """A 429 (e.g. NVD's burst-protection quirk) must be retried with
    backoff, not propagated as a hard failure on the first hit."""
    url = "https://example.test/feed.json"
    route = respx.get(url).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"v": 1}),
        ]
    )
    result = client.fetch(url, source="unit-test", offline=False)
    assert route.call_count == 2
    assert result.status_code == 200


@respx.mock
def test_429_exhausts_retries_and_raises(client: net.NetClient) -> None:
    url = "https://example.test/feed.json"
    respx.get(url).mock(return_value=httpx.Response(429, headers={"Retry-After": "0"}))
    with pytest.raises(httpx.HTTPStatusError):
        client.fetch(url, source="unit-test", offline=False)


@respx.mock
def test_rate_limit_override_actually_throttles_requests(
    net_paths: tuple[Path, Path, Path],
) -> None:
    """Timing-based proof that an override is not just stored but actually
    enforced by _RateLimiter.wait()."""
    allowlist_path, sources_path, data_dir = net_paths
    client = net.NetClient(
        allowlist_path=allowlist_path,
        sources_config_path=sources_path,
        data_dir=data_dir,
        # File config allows 1000 req/1s; override tightens it to 2 req/0.4s
        # (min_interval=0.2s) so we can prove enforcement cheaply in a test.
        rate_limit_overrides={"example.test": (2, 0.4)},
    )
    url = "https://example.test/feed.json"
    respx.get(url).mock(return_value=httpx.Response(200, json={"v": 1}))
    try:
        start = time.monotonic()
        client.fetch(f"{url}?a=1", source="unit-test", offline=False)
        client.fetch(f"{url}?a=2", source="unit-test", offline=False)
        elapsed = time.monotonic() - start
        # Both requests hit the same host, so the second must wait for the
        # override's min_interval (0.2s), not the file config's ~0.001s.
        assert elapsed >= 0.2
    finally:
        client.close()
