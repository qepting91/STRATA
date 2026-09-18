"""Collection Health -- per-source counts, last-fetch times, and known gaps.

Spec section 15.2: "Per-source last-fetch time, record counts, failures,
and corpus entries with fewer than two independent citations. The gaps
page." Spec section 15.7 singles this page out as the one to linger on
in a demo -- "showing what you failed to collect, live, is a stronger
analyst signal than any chart."
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from strata.ui.components.graph_view import render_graph
from strata.ui.data import load_collection_health, load_handoff_projection

st.set_page_config(page_title="Collection Health - STRATA", layout="wide")
st.title("Collection Health")
st.caption(
    "The honest page: what was actually collected, when, and what is "
    "known to still be missing."
)

health = load_collection_health()

st.subheader("Latest fetch per source")
latest = health["latest_fetches"]
if latest:
    st.dataframe(
        pd.DataFrame(
            [{"source": k, "latest_fetched_at (UTC)": v} for k, v in latest.items()]
        ),
        width="stretch",
        hide_index=True,
    )
    st.caption(
        "Every value above is UTC. Rows marked \"(date-only)\" come from "
        "corpus/citations.yaml's `retrieved` field, which records a date "
        "only (no time-of-day) -- not a display truncation."
    )
else:
    st.warning("No source rows found -- run `strata collect` first.")

col_a, col_b = st.columns(2)
with col_a:
    st.subheader("Nodes by type")
    node_counts = health["node_counts"]
    if node_counts:
        st.dataframe(
            pd.DataFrame(
                [{"type": k, "count": v} for k, v in node_counts.items()]
            ),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("(none)")

    st.subheader("Signals by source")
    signal_counts = health["signal_counts"]
    if signal_counts:
        st.dataframe(
            pd.DataFrame(
                [{"source": k, "count": v} for k, v in signal_counts.items()]
            ),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("(none)")

with col_b:
    st.subheader("Edges by type")
    edge_counts = health["edge_counts"]
    if edge_counts:
        st.dataframe(
            pd.DataFrame(
                [{"type": k, "count": v} for k, v in edge_counts.items()]
            ),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("(none)")

    st.subheader("Metric observations by name")
    metric_counts = health["metric_counts"]
    if metric_counts:
        st.dataframe(
            pd.DataFrame(
                [{"metric_name": k, "count": v} for k, v in metric_counts.items()]
            ),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("(none)")

st.metric("Total source rows", health["source_count"])

st.divider()
st.subheader("Corpus entries with fewer than two independent citations")
thin_groups = health["thin_citation_groups"]
if thin_groups:
    st.dataframe(
        pd.DataFrame(thin_groups).rename(
            columns={
                "group": "Group",
                "n_distinct_citations": "Distinct citations",
                "citation_ids": "Citation ids",
            }
        ),
        width="stretch",
        hide_index=True,
    )
else:
    st.info("Every corpus entry currently cites 2 or more independent sources.")

st.divider()
st.subheader("Known, documented gaps")
for gap in health["known_gaps"]:
    st.warning(gap)

st.divider()
st.subheader("Capability handoff model")
st.caption(
    "group -[:hands_off_to]-> group, plus each group's tools/exploits, "
    "rendered locally via pyvis (cdn_resources=\"local\" -- no CDN fetch)."
)
projection = load_handoff_projection()
render_graph(projection)
