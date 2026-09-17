"""Threat Groups -- select a group, see its full profile with citations.

Spec section 15.2: "Select a group -> targeted products, exploited CVEs,
tools, techniques, handoff edges. Every row shows its source citation
inline."

Note: the corpus's targeting edges reach sector/geo, not product directly
(see enrich/consensus.py's docstring for why) -- this page shows targeted
sectors/geos plus exploited CVEs/products (via the exploits edge's own
`product` field carried in corpus, when present), matching what the graph
actually contains rather than a targeting shape the corpus never
populated.
"""

from __future__ import annotations

import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.data import load_group_detail, load_groups

st.set_page_config(page_title="Threat Groups - STRATA", layout="wide")
st.title("Threat Groups")
st.caption("Every relationship row below shows its source citation inline.")

groups_df = load_groups()

if groups_df.empty:
    st.warning("No group nodes found -- run `strata corpus load` first.")
    st.stop()

group_ids = sorted(groups_df["id"].tolist())
selected = st.selectbox("Select a threat group", group_ids)

row = groups_df[groups_df["id"] == selected].iloc[0]
attrs = row["attrs"] or {}

st.subheader(row["label"])
meta_cols = st.columns(4)
meta_cols[0].metric("Naming org", attrs.get("naming_org") or "(stub)")
meta_cols[1].metric("ICS kill-chain stage", attrs.get("ics_kill_chain_stage") or "?")
meta_cols[2].metric("Role", attrs.get("role") or "(unstated)")
aliases = attrs.get("aliases") or []
meta_cols[3].metric("Aliases", len(aliases))
if aliases:
    st.caption("Aliases: " + ", ".join(aliases))

detail = load_group_detail(selected)
outgoing = detail["outgoing"]
incoming_handoffs = detail["incoming_handoffs"]

_EDGE_LABELS = {
    "targets": "Targeted sectors / geos",
    "exploits": "Exploited CVEs",
    "uses": "Tools",
    "implements": "ATT&CK techniques",
    "hands_off_to": "Hands off access to",
}

if not outgoing and not incoming_handoffs:
    st.info(
        f"{selected!r} is a stub node (referenced via another group's "
        "hands_off_to edge, no full corpus entry authored yet -- see "
        "Collection Health for the list of thin/stub entries)."
    )

for edge_type, label in _EDGE_LABELS.items():
    rows = [e for e in outgoing if e["type"] == edge_type]
    if not rows:
        continue
    st.markdown(f"### {label}")
    for e in rows:
        cols = st.columns([1, 3, 2])
        cols[0].markdown(f"**{e['dst_type']}**")
        cols[1].markdown(e["dst_label"] or e["dst_id"])
        with cols[2]:
            render_source_footer(e["source_id"])

if incoming_handoffs:
    st.markdown("### Received handoffs (access received from)")
    for e in incoming_handoffs:
        cols = st.columns([1, 3, 2])
        cols[0].markdown(f"**{e['src_type']}**")
        cols[1].markdown(e["src_label"] or e["src_id"])
        with cols[2]:
            render_source_footer(e["source_id"])
