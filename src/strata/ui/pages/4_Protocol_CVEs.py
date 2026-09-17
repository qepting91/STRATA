"""Protocol CVEs -- real involves edges + the classifier's own measured error rate.

Spec section 15.2: "The labelled dataset. Volume by protocol over time,
plus the confusion matrix from the 200-CVE validation set -- showing your
own error rate in the UI, not buried in a README."

Redesign note (this session): the previous version of this page showed a
bare row like "CVE-2017-12233 | EtherNet/IP | keyword:cip+source:nvd"
with no context about what the CVE actually is -- an analyst cannot tell
*why* the classifier matched it, only that it did. This version adds (1)
an explicit "why this page exists" explainer up front, and (2) the real
CVE description/CSAF product-tree excerpt the classifier actually
matched against, shown alongside each edge, pulled from the vuln node's
own attrs (see ui/data.py's load_protocol_edges()).

Second redesign note (this session): a CVE can legitimately have *two*
real `involves` edges to the same protocol -- one from its NVD
description matching, one from its CSAF advisory product-tree text
matching (`enrich/protocol.py` writes both independently, since each is
its own citable claim; see e.g. the real CVE-2026-78012, which matches
EtherNet/IP via both). Rendering one card per raw edge duplicated that
CVE on the page. Cards are now grouped by (CVE, protocol): one card per
real distinct match, with every contributing source shown as its own
"Matched via" tag underneath -- so multi-source corroboration is visible
as a feature (this finding is doubly confirmed), not a display bug.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.data import load_protocol_edges, load_validation_labels

st.set_page_config(page_title="Protocol CVEs - STRATA", layout="wide")
st.title("Protocol CVEs")
st.markdown(
    "**What this page shows:** which of this corpus's CVEs are described "
    "as involving a specific ICS-native protocol implementation (e.g. "
    "EtherNet/IP, Modbus, DNP3, CIP) -- not just a CVE affecting some "
    "edge/enterprise IT device that happens to sit in an OT environment. "
    "That distinction matters because a protocol-native CVE is inherently "
    "OT-relevant regardless of which Purdue level the affected product "
    "sits at: a flaw in an EtherNet/IP or CIP stack implementation can "
    "show up in devices spanning Level 1 field controllers through Level "
    "3.5 gateways alike.\n\n"
    "**How it works:** a small keyword-rule classifier (`config/"
    "protocols.yaml`, run by `enrich/protocol.py`) pattern-matches each "
    "CVE's own NVD description and, where available, the CISA CSAF "
    "advisory's product-tree text against a list of protocol names/"
    "keywords. It is a real, working classifier over real text, not a "
    "hand-curated list -- and it is not perfect. The confusion-matrix "
    "section below shows its own measured precision/recall against a "
    "real, checked-in 200-CVE hand-labeled validation set, so a reader "
    "can calibrate how much to trust the involves edges shown above it."
)

edges_df = load_protocol_edges()

st.subheader("Real involves edges")
if edges_df.empty:
    st.warning(
        "No involves edges found. Run `strata build` (enrich.protocol.run) "
        "against a graph with NVD description text first."
    )
else:
    distinct_matches = edges_df.groupby(["cve", "protocol"], sort=False)
    n_distinct = distinct_matches.ngroups

    metric_cols = st.columns(2)
    metric_cols[0].metric("Distinct CVE-protocol matches", n_distinct)
    metric_cols[1].metric("Total involves edges (incl. multi-source)", len(edges_df))
    st.caption(
        "Each card below is one real, distinct CVE-protocol match. Where a "
        "CVE's own NVD description *and* its CSAF advisory product-tree "
        "text both independently matched the same protocol, that shows up "
        "as more than one 'Matched via' tag on the same card -- "
        "corroboration, not a duplicate row."
    )
    for (cve, protocol), group in distinct_matches:
        with st.container(border=True):
            header_cols = st.columns([2, 2])
            header_cols[0].markdown(f"**{cve}**")
            header_cols[1].markdown(f"Protocol: **{protocol}**")

            first_with_description = group[group["description_excerpt"].notna()]
            first_with_csaf = group[group["csaf_excerpt"].notna()]
            if not first_with_description.empty:
                st.markdown("*NVD description:*")
                st.markdown(f"> {first_with_description.iloc[0]['description_excerpt']}")
            if not first_with_csaf.empty:
                st.markdown("*CSAF advisory product-tree text:*")
                st.markdown(f"> {first_with_csaf.iloc[0]['csaf_excerpt']}")
            if first_with_description.empty and first_with_csaf.empty:
                st.caption("(no description or product-tree text available for this CVE)")

            st.caption("Matched via:")
            for _, r in group.iterrows():
                tag_cols = st.columns([2, 3])
                tag_cols[0].markdown(f"`{r['evidence']}`")
                with tag_cols[1]:
                    render_source_footer(r["source_id"])

    distinct_df = distinct_matches.first().reset_index()

    st.markdown("### Volume by protocol")
    st.caption("Counted by distinct CVE-protocol match, not by raw edge.")
    volume = distinct_df.groupby("protocol").size().rename("count")
    st.bar_chart(volume)

    st.markdown("### Volume by protocol over time")
    if distinct_df["year"].notna().any():
        by_year = (
            distinct_df.dropna(subset=["year"])
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
