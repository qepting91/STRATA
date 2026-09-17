"""Loader for `corpus/hunt_hypotheses/<group>.yaml` files.

Unlike `normalize/corpus.py::load_corpus`, this loader never touches the
graph database -- hunt-hypothesis files are read-only reference content
consumed directly by two Streamlit pages (`8_Threat_Hunt_Template.py`,
`9_Threat_Hunt_Examples.py`). It still enforces the same provenance
discipline as every other corpus loader in this project: any `src` field
naming an unknown `corpus/citations.yaml` id fails loud at load time
rather than silently rendering an uncited claim.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from strata.normalize.hunt_hypothesis_models import HuntHypothesis


class HuntHypothesisLoadError(Exception):
    """Base class for hunt-hypothesis-loading failures."""


class HuntHypothesisCitationNotFoundError(HuntHypothesisLoadError):
    """Raised when a hunt-hypothesis YAML file's src field names an
    unknown citation id (not present in corpus/citations.yaml)."""


class HuntHypothesisValidationError(HuntHypothesisLoadError):
    """Raised when a hunt-hypothesis YAML file fails pydantic validation."""


def _load_citations(citations_path: Path) -> dict[str, dict]:
    if not citations_path.exists():
        return {}
    data = yaml.safe_load(citations_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise HuntHypothesisValidationError(
            f"{citations_path} must be a YAML mapping of citation id -> fields"
        )
    return data


def load_hunt_hypotheses(
    hunt_hypotheses_dir: Path | str = "corpus/hunt_hypotheses",
    citations_path: Path | str = "corpus/citations.yaml",
) -> dict[str, HuntHypothesis]:
    """Read and validate every hunt-hypothesis YAML file in a directory.

    Args:
        hunt_hypotheses_dir: Directory containing one YAML file per
            example group (e.g. azurite.yaml, voltzite.yaml,
            pyroxene.yaml). Missing/empty directory returns {}.
        citations_path: Path to corpus/citations.yaml, used to validate
            every `src` field actually resolves to a known citation id.

    Returns:
        A dict keyed by each file's own `group_id` field (not the
        filename -- the two need not match, though they should by
        convention).

    Raises:
        HuntHypothesisValidationError: If a file fails pydantic
            validation or is not a YAML mapping.
        HuntHypothesisCitationNotFoundError: If any `src` field names a
            citation id absent from corpus/citations.yaml.
    """
    hunt_hypotheses_dir = Path(hunt_hypotheses_dir)
    citations = _load_citations(Path(citations_path))

    hypotheses: dict[str, HuntHypothesis] = {}
    if not hunt_hypotheses_dir.exists():
        return hypotheses

    for path in sorted(hunt_hypotheses_dir.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        try:
            entry = HuntHypothesis.model_validate(raw)
        except ValidationError as exc:
            raise HuntHypothesisValidationError(f"{path}: {exc}") from exc

        if entry.src not in citations:
            raise HuntHypothesisCitationNotFoundError(
                f"{path}: unknown citation id {entry.src!r} in top-level "
                "src -- add it to corpus/citations.yaml before referencing "
                "it from a hunt-hypothesis YAML file"
            )
        for note in entry.cmf_notes:
            if note.src is not None and note.src not in citations:
                raise HuntHypothesisCitationNotFoundError(
                    f"{path}: unknown citation id {note.src!r} in a "
                    "cmf_notes entry -- add it to corpus/citations.yaml "
                    "before referencing it from a hunt-hypothesis YAML file"
                )

        hypotheses[entry.group_id] = entry

    return hypotheses
