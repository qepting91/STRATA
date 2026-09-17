"""Corpus loader: citations.yaml + groups/*.yaml -> graph.

Per the spec's architecture (section 2), the hand-curated corpus feeds
directly into model/ rather than through collect/+normalize/'s fetch-based
pipeline -- there is no HTTP fetch here, just local YAML files validated
against normalize/models.py's pydantic models and written into the same
SQLite graph the collectors populate.

Provenance is still non-negotiable: every edge this loader writes cites a
source_id resolved from corpus/citations.yaml. If a group YAML file's src
field names a citation id that is not in the registry, this raises
CitationNotFoundError at load time (fail loud) rather than silently
skipping the edge.

Any group referenced via hands_off_to that does not have its own
corpus/groups/*.yaml file is stub-created: a bare group node (id + label
only, no naming_org/role/etc attrs) so the edge is valid without
inventing an uncited full profile for it. load_corpus's return value
reports which groups were stub-created vs fully loaded so the CLI can
print that distinction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from strata.model import store
from strata.normalize.models import GroupCorpusEntry


class CorpusLoadError(Exception):
    """Base class for corpus-loading failures."""


class CitationNotFoundError(CorpusLoadError):
    """Raised when a group YAML src field names an unknown citation id."""


class CorpusValidationError(CorpusLoadError):
    """Raised when a group YAML file fails pydantic validation."""


@dataclass
class CorpusLoadSummary:
    """Summary of one load_corpus() call, for the CLI to print."""

    nodes: int = 0
    edges: int = 0
    sources: int = 0
    groups_loaded: list[str] = field(default_factory=list)
    groups_stubbed: list[str] = field(default_factory=list)


def _load_citations(citations_path: Path) -> dict[str, dict]:
    if not citations_path.exists():
        return {}
    data = yaml.safe_load(citations_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise CorpusValidationError(
            f"{citations_path} must be a YAML mapping of citation id -> fields"
        )
    return data


def _resolve_source_id(
    citation_id: str,
    citations: dict[str, dict],
    conn,
    fetched_at: str,
    ensured_sources: set[str],
) -> str:
    if citation_id not in citations:
        raise CitationNotFoundError(
            f"unknown citation id {citation_id!r}: add it to "
            "corpus/citations.yaml before referencing it from a group YAML file"
        )
    if citation_id not in ensured_sources:
        citation = citations[citation_id]
        store.insert_source(
            conn,
            id=citation_id,
            name="corpus",
            url=citation.get("url"),
            fetched_at=citation.get("retrieved") or fetched_at,
            sha256=None,
            http_status=None,
        )
        ensured_sources.add(citation_id)
    return citation_id


def load_corpus(
    conn,
    corpus_dir: Path | str = "corpus",
) -> CorpusLoadSummary:
    """Load citations.yaml + groups/*.yaml into the graph.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.
        corpus_dir: Root directory containing citations.yaml and a
            groups/ subdirectory of per-group YAML files.

    Returns:
        A CorpusLoadSummary with node/edge/source counts and the list of
        fully-loaded vs stub-created group ids.

    Raises:
        CitationNotFoundError: If any src field names an unknown
            citation id.
        CorpusValidationError: If a group YAML file fails schema
            validation.
    """
    corpus_dir = Path(corpus_dir)
    citations = _load_citations(corpus_dir / "citations.yaml")
    groups_dir = corpus_dir / "groups"

    fetched_at = datetime.now(UTC).isoformat()
    ensured_sources: set[str] = set()
    summary = CorpusLoadSummary()

    entries: dict[str, GroupCorpusEntry] = {}
    if groups_dir.exists():
        for path in sorted(groups_dir.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            try:
                entry = GroupCorpusEntry.model_validate(raw)
            except ValidationError as exc:
                raise CorpusValidationError(f"{path}: {exc}") from exc
            entries[entry.id] = entry

    def _resolve(src: str) -> str:
        return _resolve_source_id(src, citations, conn, fetched_at, ensured_sources)

    known_group_ids = set(entries.keys())
    referenced_group_ids: set[str] = set()
    for entry in entries.values():
        for handoff in entry.hands_off_to:
            referenced_group_ids.add(handoff.group)

    stub_group_ids = referenced_group_ids - known_group_ids

    # Pre-pass: create every group node (fully-loaded and stub) before any
    # edges are written. Otherwise a group referenced via hands_off_to
    # that also happens to have its own corpus file later in sorted glob
    # order (e.g. alpha -> beta, where beta.yaml sorts after alpha.yaml)
    # would fail edge insertion with a dangling node FK.
    for entry in entries.values():
        group_attrs = json.dumps(
            {
                "name": entry.name,
                "naming_org": entry.naming_org,
                "ics_kill_chain_stage": entry.ics_kill_chain_stage,
                "role": entry.role,
                "aliases": [a.name for a in entry.aliases],
            },
            sort_keys=True,
        )
        store.insert_node(
            conn,
            id=entry.id,
            type="group",
            label=entry.name,
            attrs=group_attrs,
            created_at=fetched_at,
        )
        summary.nodes += 1
        summary.groups_loaded.append(entry.id)

    for group_id in sorted(stub_group_ids):
        store.insert_node(
            conn, id=group_id, type="group", label=group_id,
            attrs=None, created_at=fetched_at,
        )
        summary.nodes += 1
        summary.groups_stubbed.append(group_id)

    for entry in entries.values():
        if entry.targets is not None:
            src_id = _resolve(entry.targets.src)
            for sector in entry.targets.sectors:
                sector_id = f"sector-{sector}"
                store.insert_node(
                    conn, id=sector_id, type="sector", label=sector,
                    attrs=None, created_at=fetched_at,
                )
                summary.nodes += 1
                store.insert_edge(
                    conn,
                    id=f"{entry.id}--targets--{sector_id}",
                    src_id=entry.id, dst_id=sector_id,
                    type="targets", source_id=src_id,
                )
                summary.edges += 1
            for geo in entry.targets.geos:
                geo_id = f"geo-{geo}"
                store.insert_node(
                    conn, id=geo_id, type="geo", label=geo,
                    attrs=None, created_at=fetched_at,
                )
                summary.nodes += 1
                store.insert_edge(
                    conn,
                    id=f"{entry.id}--targets--{geo_id}",
                    src_id=entry.id, dst_id=geo_id,
                    type="targets", source_id=src_id,
                )
                summary.edges += 1

        for exploit in entry.exploits:
            src_id = _resolve(exploit.src)
            store.insert_node(
                conn, id=exploit.cve, type="vuln", label=exploit.cve,
                attrs=None, created_at=fetched_at,
            )
            summary.nodes += 1
            store.insert_edge(
                conn,
                id=f"{entry.id}--exploits--{exploit.cve}",
                src_id=entry.id, dst_id=exploit.cve,
                type="exploits", source_id=src_id,
                # first_seen (if the corpus entry has one) is stored in the
                # edge's note column -- the same mechanism enrich/protocol.py
                # uses for classifier evidence, applied here to a different
                # edge type: an ISO date string, not evidence text. Read
                # back by enrich/timeline.py's disclosure_to_group_use
                # computation via store.get_exploits_edges_with_note().
                note=exploit.first_seen,
            )
            summary.edges += 1

        for tool in entry.tools:
            src_id = _resolve(tool.src)
            tool_id = f"tool-{tool.name.lower().replace(' ', '_')}"
            store.insert_node(
                conn, id=tool_id, type="tool", label=tool.name,
                attrs=json.dumps({"class": tool.tool_class, "oss": tool.oss}),
                created_at=fetched_at,
            )
            summary.nodes += 1
            store.insert_edge(
                conn,
                id=f"{entry.id}--uses--{tool_id}",
                src_id=entry.id, dst_id=tool_id,
                type="uses", source_id=src_id,
            )
            summary.edges += 1

        for technique in entry.techniques:
            src_id = _resolve(technique.src)
            store.insert_node(
                conn, id=technique.attack_id, type="technique",
                label=technique.attack_id,
                attrs=json.dumps({"matrix": technique.matrix}),
                created_at=fetched_at,
            )
            summary.nodes += 1
            store.insert_edge(
                conn,
                id=f"{entry.id}--implements--{technique.attack_id}",
                src_id=entry.id, dst_id=technique.attack_id,
                type="implements", source_id=src_id,
            )
            summary.edges += 1

        for handoff in entry.hands_off_to:
            src_id = _resolve(handoff.src)
            store.insert_edge(
                conn,
                id=f"{entry.id}--hands_off_to--{handoff.group}",
                src_id=entry.id, dst_id=handoff.group,
                type="hands_off_to", source_id=src_id,
            )
            summary.edges += 1

    summary.sources = len(ensured_sources)
    return summary
