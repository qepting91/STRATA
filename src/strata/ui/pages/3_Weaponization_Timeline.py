"""Weaponization Timeline -- disclosure-to-PoC / PoC-to-KEV interval metrics.

Spec section 15.2's illustrative content (scatter/box plot by group,
filterable by Purdue level/sector) assumes a data volume this project
does not have yet at the per-CVE-interval level: disclosure_to_poc_days
and poc_to_kev_days each have exactly 1 real observation, and
disclosure_to_group_use has 5 (all SYLVANITE). See enrich/timeline.py's
docstring for the honest scope limitation behind that. Purdue-level/
sector filtering is skipped entirely for the same reason: metric_observation
rows key on node_id (a CVE), and joining that to a product's Purdue level
would require a CVE -> product -> Purdue-level chain that is only
populated for a small, disjoint set of CVEs from the ones with timeline
metrics today -- filtering on it would silently produce empty results for
the entire real dataset. Noted here rather than shipped as a broken
control.

Redesign note: patch_available_at_kev is a different shape entirely --
~1,700 real observations, but each one is a near-binary 0.0/1.0 value
(patched before KEV listing, or not). Rendering that as a raw
st.bar_chart with each CVE's own string id as the x-axis category is an
unreadable wall of ~1,700 illegible bars (confirmed live via a real
screenshot). A per-item bar chart is the wrong tool for a large,
near-binary metric; the right one is a summary breakdown
(count/percentage), computed directly from these exact
metric_observation rows below.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.data import load_timeline_metrics

st.set_page_config(page_title="Weaponization Timeline - STRATA", layout="wide")
st.title("Weaponization Timeline")
st.caption(
    "disclosure_to_poc_days / poc_to_kev_days / detection_lag_days / "
    "disclosure_to_group_use / patch_available_at_kev -- point-in-time "
    "metric_observation rows only, never a mutable scalar column. Charts "
    "below are chosen for each metric's actual shape: a large, near-binary "
    "metric gets a percentage summary, not a wall of one bar per CVE; a "
    "handful of real data points get a real table, not a fake chart."
)

# Negative-value interpretation notes, keyed by metric_name -- shown only
# when a metric's real observed rows actually include a negative value,
# so the note is never displayed as boilerplate for a metric that has no
# such row.
_NEGATIVE_VALUE_NOTES = {
    "disclosure_to_poc_days": (
        "A negative value means the earliest corroborated public PoC "
        "predates this project's own t_disclosed date for the CVE."
    ),
    "poc_to_kev_days": (
        "A negative value means the CVE was added to the CISA KEV catalog "
        "before the earliest corroborated public PoC appeared."
    ),
    "detection_lag_days": (
        "A negative value means a nuclei detection template existed before "
        "the earliest corroborated public PoC."
    ),
    "disclosure_to_group_use": (
        "A negative value means the group's own first observed use of this "
        "CVE predates this project's own t_disclosed date for it -- i.e. "
        "real-world exploitation began before the vulnerability's public "
        "disclosure milestone (a zero-day-style use, not a post-disclosure "
        "one)."
    ),
}

_COLUMN_LABELS = {
    "node_id": "CVE",
    "value": "Interval (days)",
    "observed_at": "Observed at",
}


def _is_effectively_binary(values: pd.Series) -> bool:
    """True if every non-null value in `values` is 0.0 or 1.0."""
    unique_values = set(values.dropna().unique().tolist())
    return bool(unique_values) and unique_values.issubset({0.0, 1.0})


df = load_timeline_metrics()

if df.empty:
    st.warning(
        "No timeline metrics found. Run `strata build` (which calls "
        "enrich.timeline.run) against a graph with signal data first."
    )
    st.stop()

metric_names = sorted(df["metric_name"].unique().tolist())

st.subheader("Synthesis")
st.info(
    f"{len(df)} total metric_observation row(s) across {len(metric_names)} "
    "metric(s). Purdue-level/sector filtering is skipped -- see this "
    "page's module docstring for why."
)

st.divider()

for metric_name in metric_names:
    subset = df[df["metric_name"] == metric_name]
    st.markdown(f"### {metric_name}")

    if metric_name == "patch_available_at_kev" and _is_effectively_binary(
        subset["value"]
    ) and len(subset) >= 3:
        n = len(subset)
        pct_before = float(subset["value"].mean())
        n_after = max(n - round(n * pct_before), 0)
        n_before = n - n_after

        cols = st.columns(3)
        cols[0].metric("CVEs scored", f"{n:,}")
        cols[1].metric("Patched before KEV listing", f"{pct_before * 100:.1f}%")
        cols[2].metric(
            "Patched only after KEV listing",
            f"{(1 - pct_before) * 100:.1f}% ({n_after:,} CVEs)",
        )
        proportion_df = pd.DataFrame(
            {"count": [n_before, n_after]},
            index=["Patched before KEV", "Patched only after KEV"],
        )
        st.bar_chart(proportion_df)
        with st.expander(f"Show all {n:,} underlying rows"):
            st.dataframe(
                subset.rename(columns=_COLUMN_LABELS).reset_index(drop=True),
                width="stretch",
            )

    elif len(subset) < 3:
        st.caption(
            f"n={len(subset)} -- too few points for a meaningful "
            "distribution chart; showing the real row(s) instead."
        )
        negative_note = _NEGATIVE_VALUE_NOTES.get(metric_name)
        if negative_note and (subset["value"] < 0).any():
            st.info(negative_note)
        st.dataframe(
            subset[["node_id", "value", "observed_at"]]
            .rename(columns=_COLUMN_LABELS)
            .reset_index(drop=True),
            width="stretch",
            hide_index=True,
        )
        for _, r in subset.iterrows():
            render_source_footer(r["source_id"])

    elif _is_effectively_binary(subset["value"]):
        # Generic fallback for any other binary/near-binary metric with
        # enough rows to summarize -- same summary shape as
        # patch_available_at_kev above.
        n = len(subset)
        pct_true = float(subset["value"].mean())
        n_true = int(round(n * pct_true))
        n_false = n - n_true
        cols = st.columns(2)
        cols[0].metric("Observations", f"{n:,}")
        cols[1].metric("Value = 1.0", f"{pct_true * 100:.1f}% ({n_true:,})")
        st.bar_chart(pd.DataFrame({"count": [n_false, n_true]}, index=["0.0", "1.0"]))

    else:
        # Genuinely continuous data with enough points for a real
        # distribution view -- not currently hit by any metric in this
        # project's real data (all continuous metrics today have n<3),
        # kept here so a future larger continuous metric renders a real
        # histogram rather than falling through to an unreadable
        # per-item bar chart again.
        negative_note = _NEGATIVE_VALUE_NOTES.get(metric_name)
        if negative_note and (subset["value"] < 0).any():
            st.info(negative_note)
        binned = pd.cut(subset["value"], bins=min(10, subset["value"].nunique()))
        histogram = binned.value_counts().sort_index()
        histogram.index = histogram.index.astype(str)
        st.bar_chart(histogram)
        st.dataframe(
            subset[["node_id", "value", "observed_at"]]
            .rename(columns=_COLUMN_LABELS)
            .reset_index(drop=True),
            width="stretch",
            hide_index=True,
        )

    st.divider()
