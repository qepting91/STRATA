"""Shared pytest fixtures for the STRATA test suite."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from strata.model import store


@pytest.fixture
def db_conn(tmp_path: Path) -> sqlite3.Connection:
    """A fresh, schema-initialized SQLite connection backed by a temp file."""
    conn = store.get_connection(tmp_path / "strata_test.db")
    yield conn
    conn.close()


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the tests/fixtures directory."""
    return Path(__file__).parent / "fixtures"
