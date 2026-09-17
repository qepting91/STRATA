"""Protocol CVEs -- real involves edges + the classifier's own measured error rate.

Spec section 15.2: "The labelled dataset. Volume by protocol over time,
plus the confusion matrix from the 200-CVE validation set -- showing your
own error rate in the UI, not buried in a README."
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.data import load_protocol_edges, load_validation_labels

st.set_page_config(page_title="Protocol CVEs - STRATA", layout="wide")
st.title("Protocol CVEs")
st.caption(
    "Every vuln -[:involves]-> protocol edge the classifier has written, "
    "plus the classifier's own measured precision/recall from a real, "
    "checked-in 200-CVE hand-labeled validation set."
)

edges_df = load_protocol_edges()

st.subheader("Real involves edges")
if edges_df.empty:
    st.warning(
        "No involves edges found. Run `strata build` (enrich.protocol.run) "
        "against a graph with NVD description text first."
    )
else:
    st.metric("Total involves edges", len(edges_df))
    st.dataframe(edges_df.drop(columns=["source_id"]), use_container_width=True)
    st.caption("Sources for each edge:")
    for _, r in edges_df.iterrows():
        cols = st.columns([1, 4])
        cols[0].markdown(f"**{r['cve']}**")
        with cols[1]:
            render_source_footer(r["source_id"])

    st.markdown("### Volume by protocol")
    volume = edges_df.groupby("protocol").size().rename("count")
    st.bar_chart(volume)

    st.markdown("### Volume by protocol over time")
    if edges_df["year"].notna().any():
        by_year = (
            edges_df.dropna(subset=["year"])
            .groupby(["year", "protocol"])
            .size()
            .rename("count")
            .reset_index()
            .pivot(index="year", columns="protocol", values="count")
            .fillna(0)
        )
        st.bar_chart(by_year)
    else:
        st.caption(
            "No nvd_published year is available for any involved CVE -- "
            "skipping the by-year chart rather than plotting an all-null axis."
        )

st.divider()
st.subheader("Classifier validation set (real, checked-in ground truth)")

labels = load_validation_labels()
summary = labels.get("labeling_summary") or {}

if not summary:
    st.warning("No validation-set fixture found at the expected path.")
else:
    tp = summary.get("n_true_positives", 0)
    fp = summary.get("n_false_positives", 0)
    n_neg_reviewed = summary.get("n_negatives_reviewed", 0)
    fn = summary.get("n_false_negatives_found", 0)
    tn = max(n_neg_reviewed - fn, 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None

    metric_cols = st.columns(2)
    metric_cols[0].metric(
        "Precision", f"{precision:.2f}" if precision is not None else "n/a"
    )
    metric_cols[1].metric("Recall", f"{recall:.2f}" if recall is not None else "n/a")

    st.markdown("**Confusion matrix** (candidate positives + candidate negatives):")
    confusion = pd.DataFrame(
        {
            "Predicted protocol": [tp, fp],
            "Predicted no protocol": [fn, tn],
        },
        index=["Actual protocol", "Actual no protocol"],
    )
    st.table(confusion)

    st.caption(labels.get("methodology") or "")
    st.caption(summary.get("notes") or "")
