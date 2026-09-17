"""Visibility Gaps -- the telemetry requirement matrix, sorted by difficulty.

Spec section 15.2: "Telemetry matrix sorted by cost-to-close, with the
associated hunt technique per row."
"""

from __future__ import annotations

import streamlit as st

from strata.ui.data import load_telemetry_matrix

st.set_page_config(page_title="Visibility Gaps - STRATA", layout="wide")
st.title("Visibility Gaps")
st.caption(
    "config/telemetry_matrix.yaml -- hunt technique, required telemetry, "
    "typical OT collection status, and difficulty, sorted hardest-first."
)

df = load_telemetry_matrix()

if df.empty:
    st.warning("No telemetry matrix rows found at config/telemetry_matrix.yaml.")
else:
    st.dataframe(
        df.rename(
            columns={
                "hunt": "Hunt technique",
                "telemetry_required": "Telemetry required",
                "typically_collected_in_ot": "Typically collected in OT",
                "difficulty": "Difficulty",
            }
        ),
        use_container_width=True,
        hide_index=True,
    )
