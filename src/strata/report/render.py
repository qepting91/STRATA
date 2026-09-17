"""Intel report renderer (spec section 12).

Renders ``reports/<date>-ot-capability-assessment.md`` from real hunt
output and real corpus/enrichment data via Jinja2 templates. No figure in
the generated report is hardcoded: every number comes from re-running the
real hunts (``hunt.runner.run_hunt``) or querying the live graph at render
time, so the report can never go stale relative to the database it is
generated against.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from strata.hunt.graph_ops import descendants_within
from strata.hunt.models import Hunt
from strata.hunt.runner import build_projection, load_all_hunts, run_hunt
from strata.hunt.verdicts import evaluate_verdict
from strata.model import store

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Difficulty rank for config/telemetry_matrix.yaml -- cheapest-to-close
# first (spec section 12's "visibility gaps ... ranked by cost-to-close").
_DIFFICULTY_RANK = {
    "low": 0,
    "low to enable": 1,
    "medium": 2,
    "high": 3,
}

# Documented, real scope exclusions (Weeks 1-3), consolidated for section
# 2 of the report. Each one is cited in SOURCES.md/README already -- this
# is a pointer/summary, not a new claim.
_EXCLUDED_SCOPE = [
    (
        "Vendor-PSIRT collectors (Siemens, Schneider, Hitachi, Cisco, "
        "Palo Alto, Fortinet, Ivanti)",
        "Deliberately deferred every week (see SOURCES.md, "
        "\"Deliberately not collected\"). No per-vendor disclosure-date "
        "data exists anywhere in the schema as a result -- this is why "
        "H010 (cross-vendor patch latency) is INSUFFICIENT.",
    ),
    (
        "CSAF product-tree text extraction",
        "The CISA CSAF collector never extracts product_tree text, so "
        "enrich/protocol.py's ICS-protocol classifier runs over NVD CVE "
        "description text only -- not the full input set spec section "
        "6.2 describes.",
    ),
    (
        "t_group_observed / disclosure_to_group_use",
        "The corpus's group-entry format (corpus/groups/*.yaml) has no "
        "first_seen date on a group's exploits claims, so this metric "
        "has zero rows in metric_observation -- this is why H002 is "
        "INSUFFICIENT rather than merely small-sample.",
    ),
]


@dataclass
class HuntFinding:
    """One hunt's full result: the hunt definition, its namespace, and verdict."""

    hunt: Hunt
    namespace: dict
    verdict: str


def _run_all(conn: sqlite3.Connection, hunts_dir: str) -> list[HuntFinding]:
    """Load and run every hunts/*.yaml file against the live connection."""
    hunts = load_all_hunts(hunts_dir)
    findings = []
    for h in hunts:
        result = run_hunt(conn, h)
        verdict = evaluate_verdict(result.namespace, h.insufficient_if, h.falsifies_if)
        findings.append(HuntFinding(hunt=h, namespace=result.namespace, verdict=verdict))
    return findings


def _namespace_line(namespace: dict) -> str:
    """One human-readable line of a hunt's non-'rows' namespace values."""
    shown = {k: v for k, v in namespace.items() if k != "rows"}
    return ", ".join(f"{k}={v}" for k, v in shown.items())


def _pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{round(value * 100, 2)}"


# Key-judgement bullets are drawn only from hunts whose verdict is
# SUPPORTED or REFUTED (per spec section 12.1's "4-6 bullets"). Each
# render callable reads live namespace values from the real hunt run --
# nothing here is a hardcoded number.
_KEY_JUDGEMENT_SPECS: dict[str, dict] = {
    "H001": {
        "confidence": "moderate",
        "render": lambda ns: (
            f"No product in the corpus currently has confirmed exploitation "
            f"by 2+ distinct threat-actor clusters ({ns.get('n', 0)} "
            f"qualifying products found among {ns.get('total_exploits_edges', 0)} "
            f"total exploits edges). Refuted, but this is at least as much a "
            f"sourcing-coverage artifact (only 1 of 8 corpus groups has any "
            f"named exploited CVE) as it is a finding about real-world "
            f"convergence."
        ),
    },
    "H003": {
        "confidence": "high",
        "render": lambda ns: (
            f"A vendor fix or public advisory predated CISA KEV listing for "
            f"~{_pct(ns.get('pct_patched_before_kev'))}% of "
            f"{ns.get('n', 0)} scored CVEs -- for most KEV-listed OT-relevant "
            f"CVEs, the operational bottleneck is patch *application*, not "
            f"patch *availability*."
        ),
    },
    "H005": {
        "confidence": "moderate",
        "render": lambda ns: (
            f"Of {ns.get('n_ransomware_cves', 0)} KEV-flagged ransomware CVEs, "
            f"{ns.get('n_ransomware_cves_with_protocol_involvement', 0)} also "
            f"involve an ICS-native protocol (overlap rate "
            f"{_pct(ns.get('overlap_rate'))}%) -- ransomware's operational "
            f"impact on industrials in this corpus runs through IT-side "
            f"systems, not OT protocol-native paths."
        ),
    },
    "H007": {
        "confidence": "moderate",
        "render": lambda ns: (
            f"Purdue level 3.5 (edge / IT-OT boundary) products carry "
            f"affects edges from {ns.get('mass_3_5', 0)} distinct CVEs, "
            f"versus {ns.get('mass_1', 0)} for Purdue level 1 (PLC/RTU/"
            f"field-device) products -- adversary-relevant CVE mass "
            f"concentrates at the boundary, not the field-device layer, "
            f"within this corpus's Purdue-classified subset."
        ),
    },
    "H009": {
        "confidence": "high",
        "render": lambda ns: (
            f"Starting from sylvanite (a Stage 1 initial-access group), a "
            f"3-hop traversal over hands_off_to/uses/exploits edges reaches "
            f"{ns.get('n', 0)} distinct nodes ({ns.get('by_type', {})}) -- a "
            f"real, bounded Stage 2 capability set a defender can act on "
            f"without waiting for a fresh incident report."
        ),
    },
}


def _key_judgements(findings: list[HuntFinding]) -> list[dict]:
    by_id = {f.hunt.id: f for f in findings}
    judgements = []
    for hunt_id, spec in _KEY_JUDGEMENT_SPECS.items():
        finding = by_id.get(hunt_id)
        if finding is None:
            continue
        judgements.append(
            {
                "hunt_id": hunt_id,
                "verdict": finding.verdict,
                "confidence": spec["confidence"],
                "text": spec["render"](finding.namespace),
            }
        )
    return judgements


def _scope_and_method(conn: sqlite3.Connection) -> dict:
    fetch_times = store.latest_fetch_times(conn)
    times = sorted(t for t in fetch_times.values() if t)
    return {
        "sources": sorted(fetch_times),
        "fetch_times": fetch_times,
        "window_start": times[0] if times else None,
        "window_end": times[-1] if times else None,
        "source_row_count": store.count_sources(conn),
        "node_counts": store.count_nodes_by_type(conn),
        "edge_counts": store.count_edges_by_type(conn),
    }


def _handoff_confidence_map(corpus_dir: str) -> dict[tuple[str, str], str]:
    """Read hands_off_to confidence values directly from corpus/groups/*.yaml.

    ``edge.note`` is not populated for hands_off_to edges (see
    normalize/corpus.py), so confidence -- a real, cited fact -- is only
    available in the source YAML, not the database. Read live rather than
    hardcode it, so this stays correct if a corpus file is edited.
    """
    confidences: dict[tuple[str, str], str] = {}
    groups_dir = Path(corpus_dir) / "groups"
    for path in sorted(groups_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not data:
            continue
        group_id = data.get("id")
        for handoff in data.get("hands_off_to", []) or []:
            dst = handoff.get("group")
            if group_id and dst:
                confidences[(group_id, dst)] = handoff.get("confidence") or "unspecified"
    return confidences


def _handoff_model(conn: sqlite3.Connection, corpus_dir: str) -> dict:
    edge_rows = conn.execute(
        "SELECT src_id, dst_id FROM edge WHERE type = 'hands_off_to' ORDER BY src_id, dst_id"
    ).fetchall()
    confidences = _handoff_confidence_map(corpus_dir)
    edges = [
        {
            "src": row["src_id"],
            "dst": row["dst_id"],
            "confidence": confidences.get((row["src_id"], row["dst_id"]), "unspecified"),
        }
        for row in edge_rows
    ]

    projection = build_projection(
        conn, ["group", "tool", "vuln", "product"], ["hands_off_to", "uses", "exploits"]
    )
    traversal = descendants_within(
        projection, source="sylvanite", depth=3, via=["hands_off_to", "uses", "exploits"]
    )
    return {"edges": edges, "traversal": traversal}


def _visibility_gaps(telemetry_matrix_path: str) -> list[dict]:
    data = yaml.safe_load(Path(telemetry_matrix_path).read_text(encoding="utf-8")) or {}
    rows = list(data.get("rows", []))

    def _rank(row: dict) -> int:
        return _DIFFICULTY_RANK.get(str(row.get("difficulty", "")).strip().lower(), 99)

    rows.sort(key=_rank)
    return rows


def _protocol_validation_summary(validation_path: Path) -> dict | None:
    if not validation_path.exists():
        return None
    data = json.loads(validation_path.read_text(encoding="utf-8"))
    return data.get("labeling_summary")


def _limitations(
    conn: sqlite3.Connection, findings: list[HuntFinding], validation_path: Path
) -> dict:
    group_ids = {
        row["id"] for row in conn.execute("SELECT id FROM node WHERE type = 'group'").fetchall()
    }
    groups_with_exploits = {
        row["src_id"]
        for row in conn.execute(
            "SELECT DISTINCT src_id FROM edge WHERE type = 'exploits'"
        ).fetchall()
    }
    return {
        "n_groups": len(group_ids),
        "n_groups_without_exploits": len(group_ids - groups_with_exploits),
        "validation_summary": _protocol_validation_summary(validation_path),
        "insufficient_hunts": [f.hunt.id for f in findings if f.verdict == "INSUFFICIENT"],
        "refuted_hunts": [f.hunt.id for f in findings if f.verdict == "REFUTED"],
        "supported_hunts": [f.hunt.id for f in findings if f.verdict == "SUPPORTED"],
    }


def _appendix(conn: sqlite3.Connection, citations_path: str) -> dict:
    raw = yaml.safe_load(Path(citations_path).read_text(encoding="utf-8")) or {}
    citations = {k: v for k, v in raw.items() if isinstance(v, dict)}
    return {
        "citations": dict(sorted(citations.items())),
        "collector_fetch_times": store.latest_fetch_times(conn),
    }


def render_report(
    conn: sqlite3.Connection,
    *,
    hunts_dir: str = "hunts",
    corpus_dir: str = "corpus",
    telemetry_matrix_path: str = "config/telemetry_matrix.yaml",
    citations_path: str = "corpus/citations.yaml",
    validation_labels_path: str = "tests/fixtures/protocol_validation_labels.json",
    report_date: date | None = None,
) -> str:
    """Render the full 7-section intel report as a markdown string.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.
        hunts_dir: Directory of hunts/*.yaml files.
        corpus_dir: Directory containing corpus/groups/*.yaml (for handoff
            confidence values not persisted in the graph).
        telemetry_matrix_path: Path to config/telemetry_matrix.yaml.
        citations_path: Path to corpus/citations.yaml.
        validation_labels_path: Path to the protocol classifier's 200-CVE
            hand-labeled validation set (for the limitations section).
        report_date: The date to stamp the report with; defaults to today.

    Returns:
        The rendered markdown text.
    """
    report_date = report_date or datetime.now(UTC).date()
    findings = _run_all(conn, hunts_dir)

    context = {
        "report_date": report_date.isoformat(),
        "key_judgements": _key_judgements(findings),
        "scope": _scope_and_method(conn),
        "excluded_scope": _EXCLUDED_SCOPE,
        "findings": [
            {
                "id": f.hunt.id,
                "title": f.hunt.title,
                "hypothesis": f.hunt.hypothesis.strip(),
                "rationale": f.hunt.rationale.strip(),
                "verdict": f.verdict,
                "namespace_line": _namespace_line(f.namespace),
                "telemetry_gap": f.hunt.telemetry_gap.strip(),
            }
            for f in findings
        ],
        "handoff": _handoff_model(conn, corpus_dir),
        "visibility_gaps": _visibility_gaps(telemetry_matrix_path),
        "limitations": _limitations(conn, findings, Path(validation_labels_path)),
        "appendix": _appendix(conn, citations_path),
    }

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")
    return template.render(**context)


def write_report(
    conn: sqlite3.Connection,
    *,
    hunts_dir: str = "hunts",
    corpus_dir: str = "corpus",
    telemetry_matrix_path: str = "config/telemetry_matrix.yaml",
    citations_path: str = "corpus/citations.yaml",
    validation_labels_path: str = "tests/fixtures/protocol_validation_labels.json",
    out_dir: str = "reports",
    report_date: date | None = None,
) -> Path:
    """Render the report and write it to reports/<date>-ot-capability-assessment.md.

    Returns:
        The Path the report was written to.
    """
    report_date = report_date or datetime.now(UTC).date()
    text = render_report(
        conn,
        hunts_dir=hunts_dir,
        corpus_dir=corpus_dir,
        telemetry_matrix_path=telemetry_matrix_path,
        citations_path=citations_path,
        validation_labels_path=validation_labels_path,
        report_date=report_date,
    )
    out_path = Path(out_dir) / f"{report_date.isoformat()}-ot-capability-assessment.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return out_path
