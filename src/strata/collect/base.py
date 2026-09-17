"""Collector ABC shared by all STRATA collectors.

Each collector implements a fetch -> parse -> normalize pipeline; run()
orchestrates that pipeline against a store.py-backed SQLite connection and
returns summary counts for the CLI to print.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import date
from typing import ClassVar

from strata import net
from strata.model import store


@dataclass
class SourceRecord:
    """Intermediate representation of a `source` table row."""

    id: str
    name: str
    url: str | None
    fetched_at: str
    sha256: str | None = None
    http_status: int | None = None


@dataclass
class NodeRecord:
    """Intermediate representation of a `node` table row."""

    id: str
    type: str
    label: str
    attrs: str | None
    created_at: str


@dataclass
class EdgeRecord:
    """Intermediate representation of an `edge` table row."""

    id: str
    src_id: str
    dst_id: str
    type: str
    source_id: str


class Collector(ABC):
    """Base class for a STRATA data-source collector.

    Subclasses implement `fetch`, `parse`, and `normalize`. `run` wires
    them together and persists the result via `strata.model.store`.
    """

    source_name: ClassVar[str]

    def __init__(self, net_client: net.NetClient | None = None) -> None:
        self._net = net_client or net.NetClient()
        self.since: date | None = None

    @abstractmethod
    def fetch(self, offline: bool) -> list[net.FetchResult]:
        """Fetch one or more raw payloads for this source.

        Args:
            offline: If True, serve strictly from the on-disk cache with
                zero network calls (see `strata.net.NetClient.fetch`).

        Returns:
            List of `FetchResult` objects, one per HTTP resource fetched.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, fetch_result: net.FetchResult) -> list[dict]:
        """Parse a single fetch result's raw bytes into intermediate records.

        Args:
            fetch_result: A single fetched payload.

        Returns:
            List of plain dicts representing raw parsed records. Each dict
            may carry provenance breadcrumbs (e.g. sha256, url) needed by
            `normalize`.
        """
        raise NotImplementedError

    @abstractmethod
    def normalize(
        self, raw_records: list[dict]
    ) -> tuple[list[NodeRecord], list[EdgeRecord], SourceRecord | list[SourceRecord]]:
        """Convert raw parsed records into node/edge/source rows.

        Args:
            raw_records: The concatenation of `parse()` output across all
                fetch results.

        Returns:
            A tuple of (nodes, edges, sources). `sources` may be a single
            `SourceRecord` (e.g. one shared source row for a single-payload
            feed) or a list of them (e.g. one per CSAF advisory file).
        """
        raise NotImplementedError

    def run(self, conn, offline: bool = False) -> dict:
        """Execute fetch -> parse -> normalize -> store, and return counts.

        Args:
            conn: An open `sqlite3.Connection` from `store.get_connection`.
            offline: Passed through to `fetch()`.

        Returns:
            Dict summary: {"source": source_name, "nodes": N, "edges": N,
            "sources": N}.
        """
        fetch_results = self.fetch(offline)

        raw_records: list[dict] = []
        for fr in fetch_results:
            raw_records.extend(self.parse(fr))

        nodes, edges, sources = self.normalize(raw_records)
        if isinstance(sources, SourceRecord):
            sources = [sources]

        for s in sources:
            store.insert_source(
                conn,
                id=s.id,
                name=s.name,
                url=s.url,
                fetched_at=s.fetched_at,
                sha256=s.sha256,
                http_status=s.http_status,
            )

        for n in nodes:
            store.insert_node(
                conn,
                id=n.id,
                type=n.type,
                label=n.label,
                attrs=n.attrs,
                created_at=n.created_at,
            )

        for e in edges:
            store.insert_edge(
                conn,
                id=e.id,
                src_id=e.src_id,
                dst_id=e.dst_id,
                type=e.type,
                source_id=e.source_id,
            )

        return {
            "source": self.source_name,
            "sources": len(sources),
            "nodes": len(nodes),
            "edges": len(edges),
        }
