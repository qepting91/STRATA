"""Three-state hunt verdict evaluation + terminal rendering (spec section 7.3).

Verdict logic: evaluate insufficient_if first (if true -> INSUFFICIENT);
else evaluate falsifies_if (if true -> REFUTED); else SUPPORTED.
Expressions are evaluated via simpleeval.simple_eval, never Python eval(),
per the project standing no-eval() security policy (see SECURITY.md).
"""

from __future__ import annotations

from typing import Literal

from simpleeval import simple_eval

from strata.hunt.models import Hunt

Verdict = Literal["SUPPORTED", "REFUTED", "INSUFFICIENT"]


def evaluate_verdict(namespace: dict, insufficient_if: str, falsifies_if: str) -> Verdict:
    """Evaluate a hunt three-state verdict against its result namespace.

    Args:
        namespace: The dict returned by hunt.runner.run_hunt (column names
            / computed variables a hunt YAML own expressions reference).
        insufficient_if: A boolean expression over namespace, checked first.
        falsifies_if: A boolean expression over namespace, checked second.

    Returns:
        "INSUFFICIENT" if insufficient_if is true, else "REFUTED" if
        falsifies_if is true, else "SUPPORTED".
    """
    # Restrict evaluation to plain names (no attribute/function access) --
    # simple_eval already refuses arbitrary code execution; passing only
    # the namespace dict as `names` further ensures no builtins leak in.
    if simple_eval(insufficient_if, names=namespace):
        return "INSUFFICIENT"
    if simple_eval(falsifies_if, names=namespace):
        return "REFUTED"
    return "SUPPORTED"


def render_hunt_result(hunt: Hunt, namespace: dict, verdict: Verdict) -> str:
    """Render one hunt's result in the spec section 7.3 terminal table format.

    Refuted and insufficient verdicts get exactly the same visual weight as
    supported ones -- no dimming, no de-emphasis -- per the spec explicit
    design intent ("a board that is all green is evidence of a curated
    dataset, not a good analyst").
    """
    lines = [
        f"{hunt.id}  {hunt.title}",
        "-" * min(len(f"{hunt.id}  {hunt.title}"), 78),
        f"VERDICT: {verdict}",
        "",
    ]

    rows = namespace.get("rows")
    if isinstance(rows, list) and rows:
        for row in rows[:10]:
            parts = [f"{k}={v}" for k, v in row.items() if k != "rows"]
            lines.append("  " + "  ".join(parts))
        if len(rows) > 10:
            lines.append(f"  ... ({len(rows) - 10} more rows)")
    else:
        shown = {k: v for k, v in namespace.items() if k != "rows"}
        if shown:
            lines.append("  " + "  ".join(f"{k}={v}" for k, v in shown.items()))

    lines.append("")
    lines.append(f"telemetry_gap: {hunt.telemetry_gap.strip()}")
    return "\n".join(lines)
