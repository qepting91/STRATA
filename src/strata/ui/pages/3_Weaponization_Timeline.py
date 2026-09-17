"""Weaponization Timeline -- disclosure-to-PoC / PoC-to-KEV interval metrics.

Spec section 15.2's illustrative content (scatter/box plot by group,
filterable by Purdue level/sector) assumes a data volume this project
does not have yet: only 1 disclosure_to_poc_days row and 1
poc_to_kev_days row currently exist (Week 3's real, honestly-reported
numbers -- see enrich/timeline.py's docstring for why
disclosure_to_group_use, the by-group metric the spec example plots, was
never computed at all). This page is written to render sensibly with
that near-empty reality rather than fake a richer chart: a simple table
plus a bar chart per metric name, with an explicit note when n is too
small to plot meaningfully.

Purdue-level/sector filtering is skipped: metric_observation rows key on
node_id (a CVE), and joining that to a product's Purdue level would
require a CVE -> product -> Purdue-level chain that is only populated for
a small, disjoint set of CVEs from the ones with timeline metrics today
-- filtering on it would silently produce empty results for the entire
real dataset. Noted here rather than shipped as a broken control.
"""

from __future__ import annotations

import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.data import load_timeline_metrics

st.set_page_config(page_title="Weaponization Timeline - STRATA", layout="wide")
st.title("Weaponization Timeline")
st.caption(
    "disclosure_to_poc_days / poc_to_kev_days / detection_lag_days / "
    "patch_available_at_kev -- point-in-time metric_observation rows only, "
    "never a mutable scalar column."
)

df = load_timeline_metrics()

if df.empty:
    st.warning(
        "No timeline metrics found. Run `strata build` (which calls "
        "enrich.timeline.run) against a graph with signal data first."
    )
    st.stop()

metric_names = sorted(df["metric_name"].unique().tolist())

st.info(
    f"{len(df)} total metric_observation row(s) across {len(metric_names)} "
    "metric(s). Filterable by Purdue level/sector is skipped this pass -- "
    "see this page's module docstring for why."
)

for metric_name in metric_names:
    subset = df[df["metric_name"] == metric_name]
    st.markdown(f"### {metric_name}")
    if len(subset) < 3:
        st.caption(
            f"n={len(subset)} -- too few points for a meaningful "
            "distribution chart; showing the raw row(s) instead."
        )
        st.dataframe(
            subset[["node_id", "value", "observed_at"]].reset_index(drop=True),
            use_container_width=True,
        )
        for _, r in subset.iterrows():
            render_source_footer(r["source_id"])
    else:
        chart_df = subset[["node_id", "value"]].set_index("node_id")
        st.bar_chart(chart_df)
        st.dataframe(subset.reset_index(drop=True), use_container_width=True)
