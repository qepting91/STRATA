"""Pydantic models for the `corpus/hunt_hypotheses/<group>.yaml` format.

This mirrors `normalize/models.py`'s `GroupCorpusEntry` family (same
`extra="forbid"` discipline, same `src`-cites-a-real-citation-id
provenance rule) but is a deliberately separate, read-only reference
format: unlike every other corpus YAML, a hunt-hypothesis file is never
written into the graph database. `normalize/hunt_hypothesis_loader.py`
reads and validates these files directly for the two Streamlit "Threat
Hunt Template"/"Threat Hunt Examples" pages -- there is no
graph-writing step analogous to `normalize/corpus.py::load_corpus`.

Each hunt-hypothesis file holds only the analytical-judgment content the
graph itself can't supply: a stated hypothesis, an illustrative
stakeholder priority framing, a Collection Management Framework (CMF)
mapping of hunt steps to what STRATA's own data model can/can't
back, and what PROVED/DISPROVED/INCONCLUSIVE would concretely look like
given STRATA's real schema. Real per-group facts (targets/tools/
techniques/handoffs) are pulled live from the graph by the UI layer
(`ui/data.py::load_group_detail`), not duplicated here.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CmfNote(BaseModel):
    """One Collection Management Framework mapping row.

    Ties a specific step in the hunt's execution plan to an honest
    statement of whether STRATA's own graph/corpus can back it.
    """

    model_config = ConfigDict(extra="forbid")

    hunt_step: str
    strata_coverage: str
    # Optional: a CMF note describing a genuine gap in STRATA's own data
    # model (e.g. "NOT modeled -- needs real east-west NetFlow") is a
    # statement about this project's architecture, not an externally
    # sourced claim, so it may cite nothing. When present, it must
    # resolve against corpus/citations.yaml just like every other `src`
    # field in this codebase.
    src: str | None = None


class OutcomeCriteria(BaseModel):
    """What PROVED/DISPROVED/INCONCLUSIVE concretely look like.

    Each field is a specific, STRATA-data-grounded description (e.g.
    "no exploits edge with a first_seen date within N days") -- not
    generic hunt-methodology boilerplate.
    """

    model_config = ConfigDict(extra="forbid")

    proved: str
    disproved: str
    inconclusive: str


class HuntHypothesis(BaseModel):
    """One `corpus/hunt_hypotheses/<group_id>.yaml` file, fully validated."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    hypothesis_statement: str
    # The citation this hypothesis statement is grounded in (a real
    # corpus/citations.yaml id -- e.g. S-0008/S-0002/S-0009 for
    # azurite/voltzite/pyroxene). Required: an analytical hypothesis
    # about a specific group's real-world behavior must always trace
    # back to a real, publicly linkable document, same discipline as
    # every other citation-bearing field in this project.
    src: str
    # A short, clearly-labeled-as-illustrative stakeholder priority
    # framing (e.g. "Illustrative PIR: ..."). Not a real customer's
    # actual priority intelligence requirement -- invented for
    # demonstration purposes, and must say so plainly.
    pir_reference: str
    cmf_notes: list[CmfNote] = Field(default_factory=list)
    outcome_criteria: OutcomeCriteria
