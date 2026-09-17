"""Pydantic models mirroring the corpus YAML format (spec section 5.6).

Every citation-bearing list entry carries a `src` field naming a citation
id resolved against `corpus/citations.yaml` at load time (see
`normalize/corpus.py`). These models validate shape only; citation-id
resolution and provenance-row creation happen in the loader, not here.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Alias(BaseModel):
    """A group's known alias under another org's naming convention."""

    model_config = ConfigDict(extra="forbid")

    name: str
    org: str | None = None
    src: str


class Targets(BaseModel):
    """A group's target sectors/geos, one citation for the whole block."""

    model_config = ConfigDict(extra="forbid")

    sectors: list[str] = Field(default_factory=list)
    geos: list[str] = Field(default_factory=list)
    src: str


class Exploit(BaseModel):
    """A CVE a group is documented to have exploited.

    ``first_seen`` is an optional ISO-8601 date string for the earliest
    publicly documented date this group was observed exploiting the CVE
    (distinct from the CVE's own disclosure date). When present,
    ``normalize/corpus.py`` stores it in the ``exploits`` edge's ``note``
    column, which ``enrich/timeline.py`` reads back to compute
    ``disclosure_to_group_use``.
    """

    model_config = ConfigDict(extra="forbid")

    cve: str
    product: str | None = None
    first_seen: str | None = None
    src: str


class Tool(BaseModel):
    """A tool/malware family a group is documented to use."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str
    tool_class: str | None = Field(default=None, alias="class")
    oss: bool = False
    src: str


class Technique(BaseModel):
    """An ATT&CK technique a group is documented to implement."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str
    matrix: str = "enterprise"
    src: str


class HandsOff(BaseModel):
    """A hand-off relationship to another group (stub-created if unknown)."""

    model_config = ConfigDict(extra="forbid")

    group: str
    confidence: str | None = None
    src: str


class GroupCorpusEntry(BaseModel):
    """One `corpus/groups/<id>.yaml` file, fully validated."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    naming_org: str | None = None
    ics_kill_chain_stage: int | None = None
    role: str | None = None
    aliases: list[Alias] = Field(default_factory=list)
    targets: Targets | None = None
    exploits: list[Exploit] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)
    techniques: list[Technique] = Field(default_factory=list)
    hands_off_to: list[HandsOff] = Field(default_factory=list)


class Citation(BaseModel):
    """One `corpus/citations.yaml` entry: a publicly linkable document."""

    model_config = ConfigDict(extra="forbid")

    publisher: str
    # Nullable: a citation may be a locally-supplied document (e.g. a PDF
    # provided directly by the user) rather than a fetched web resource,
    # in which case there is no retrieval URL to cite (see S-0012 in
    # corpus/citations.yaml). The `source` table's own `url` column is
    # already nullable (schema.sql) -- this mirrors that honestly rather
    # than forcing a placeholder string.
    url: str | None = None
    retrieved: str | None = None
    supports: str | None = None
