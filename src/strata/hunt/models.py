"""Pydantic model for a hunt YAML file (spec section 7.2).

A hunt file declares exactly one execution method (`sql`, `graph`, or
`python`) and must carry the one field that method needs (`query`,
`graph_op`, or `python_fn` respectively) and none of the others -- this is
enforced by a model validator so a malformed hunt YAML fails fast at load
time, not partway through `run_hunt`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

HuntMethod = Literal["sql", "graph", "python"]


class GraphProjection(BaseModel):
    """Which node/edge types to include when building the NetworkX projection."""

    model_config = ConfigDict(extra="forbid")

    node_types: list[str]
    edge_types: list[str]


class GraphOp(BaseModel):
    """A named graph_ops.py function plus its keyword arguments."""

    model_config = ConfigDict(extra="forbid")

    projection: GraphProjection
    fn: str
    args: dict = {}


class Hunt(BaseModel):
    """One curated hunt (spec section 7.2's worked example format)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    hypothesis: str
    rationale: str
    null_hypothesis: str
    method: HuntMethod
    query: str | None = None
    graph_op: GraphOp | None = None
    python_fn: str | None = None
    falsifies_if: str
    insufficient_if: str
    telemetry_gap: str

    @model_validator(mode="after")
    def _check_method_field_pairing(self) -> Hunt:
        """Exactly the field(s) matching `method` must be set; others must be None."""
        by_method: dict[str, str] = {"sql": "query", "graph": "graph_op", "python": "python_fn"}
        required_field = by_method[self.method]
        all_fields = set(by_method.values())

        if getattr(self, required_field) is None:
            raise ValueError(
                f"hunt {self.id!r}: method={self.method!r} requires a non-null "
                f"{required_field!r} field"
            )
        for other_field in all_fields - {required_field}:
            if getattr(self, other_field) is not None:
                raise ValueError(
                    f"hunt {self.id!r}: method={self.method!r} must not set "
                    f"{other_field!r} (only {required_field!r} applies)"
                )
        return self
