"""Hunt Board -- all 10 curated hunts as cards with equal-prominence verdicts.

Spec section 15.2: "All ten hunts as cards with SUPPORTED / REFUTED /
INSUFFICIENT badges. Click through to hypothesis, query, result table,
and the falsification criterion. Refuted cards are styled with equal
weight to supported ones, deliberately."
"""

from __future__ import annotations

import json

import streamlit as st

from strata.ui.components.verdict_badge import render_verdict_badge, verdict_counts
from strata.ui.data import load_hunt_results

st.set_page_config(page_title="Hunt Board - STRATA", layout="wide")
st.title("Hunt Board")
st.caption(
    "All 10 curated hunts, computed fresh against the real local graph. "
    "A board that is all green would be evidence of a curated dataset, "
    "not a good analyst -- refuted and insufficient verdicts get the same "
    "visual weight as supported ones."
)

df = load_hunt_results()

if df.empty:
    st.warning("No hunts loaded -- check the hunts/ directory.")
else:
    counts = verdict_counts(df["verdict"].tolist())
    cols = st.columns(3)
    cols[0].metric("SUPPORTED", counts.get("SUPPORTED", 0))
    cols[1].metric("REFUTED", counts.get("REFUTED", 0))
    cols[2].metric("INSUFFICIENT", counts.get("INSUFFICIENT", 0))

    st.divider()

    for _, row in df.sort_values("id").iterrows():
        with st.container(border=True):
            header_cols = st.columns([5, 1])
            with header_cols[0]:
                st.subheader(f"{row['id']}  --  {row['title']}")
            with header_cols[1]:
                render_verdict_badge(row["verdict"])

            with st.expander("Hypothesis, method, and falsification criterion"):
                st.markdown(f"**Hypothesis:** {row['hypothesis']}")
                st.markdown(f"**Rationale:** {row['rationale']}")
                st.markdown(f"**Null hypothesis:** {row['null_hypothesis']}")
                st.markdown(f"**Method:** `{row['method']}`")
                st.markdown(f"**insufficient_if:** `{row['insufficient_if']}`")
                st.markdown(f"**falsifies_if:** `{row['falsifies_if']}`")

                st.markdown("**Result variables:**")
                try:
                    namespace = json.loads(row["namespace_json"])
                except (json.JSONDecodeError, TypeError):
                    namespace = {}
                if namespace:
                    st.json(namespace)
                else:
                    st.caption("(no result variables returned)")

                st.markdown(f"**Telemetry gap:** {row['telemetry_gap']}")
