"""Search -- keyword + dynamic filtering across every real node in the graph.

Every other page is scoped to one domain (Threat Groups, Protocol CVEs,
Weaponization Timeline, ...). This page is the cross-domain answer to
"does X exist anywhere in this graph, and what do we actually know about
it" -- a single keyword search over every node's id/label/attrs, with a
type filter and a handful of dynamic, type-conditioned filters (Purdue
level, ICS Kill Chain stage, known ransomware use) that only appear when
relevant.

Results are capped (default 300 rows) with the real total match count
shown separately -- this is a search page, not an unbounded table dump.
Selecting one result drills into its real outgoing/incoming edges, each
with its own resolvable source citation, via the same store helpers the
Threat Groups page uses.
"""

from __future__ import annotations

import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.data import (
    load_node_full,
    load_node_type_counts,
    load_purdue_level_options,
    search_nodes,
)

st.set_page_config(page_title="Search - STRATA", layout="wide")
st.title("Search")
st.caption(
    "Keyword search across every real node in the graph -- threat groups, "
    "CVEs, tools, ATT&CK techniques, products, vendors, sectors, "
    "geographies, protocols, advisories. Matches the node's own id, "
    "label, or any text inside its attrs."
)

type_counts = load_node_type_counts()
if not type_counts:
    st.warning("No nodes found. Run `strata collect`/`strata build` first.")
    st.stop()

filter_cols = st.columns([2, 2])
with filter_cols[0]:
    keyword = st.text_input(
        "Keyword", placeholder="e.g. modbus, Godzilla, ransomware, T1190, CVE-2023-46805"
    )
with filter_cols[1]:
    type_options = sorted(type_counts.keys())
    selected_types = st.multiselect(
        "Node type",
        options=type_options,
        format_func=lambda t: f"{t} ({type_counts[t]:,})",
        help="Leave empty to search every type.",
    )

# Dynamic filters: each only appears when it could plausibly narrow the
# current type selection (or when no type filter is set at all, since
# then any of these types could be part of the results).
active_types = set(selected_types) or set(type_options)
dynamic_cols = st.columns(3)
purdue_level = None
ics_stage = None
ransomware_only = None

with dynamic_cols[0]:
    if "product" in active_types:
        purdue_options = load_purdue_level_options()
        choice = st.selectbox("Purdue level", ["All"] + purdue_options)
        purdue_level = None if choice == "All" else choice
        st.caption(
            "Real, but a weaker signal than it looks: `config/purdue_map.yaml` "
            "only assigns a level to purpose-built, single-role devices "
            "(PLCs, cellular gateways, firewalls, VFDs) where the level is "
            "effectively fixed regardless of deployment. A general-purpose "
            "platform (a Windows host, a hypervisor) can sit at very "
            "different real Purdue levels depending on what's actually "
            "installed on it -- this classifier does not attempt that "
            "judgment call, and none of the mapped products require it "
            "today."
        )

with dynamic_cols[1]:
    if "group" in active_types:
        choice = st.selectbox("ICS Kill Chain stage", ["All", "1", "2"])
        ics_stage = None if choice == "All" else int(choice)

with dynamic_cols[2]:
    if "vuln" in active_types:
        choice = st.selectbox("Known ransomware use", ["All", "Known", "Unknown"])
        ransomware_only = None if choice == "All" else choice

RESULT_LIMIT = 300
results = search_nodes(
    keyword=keyword.strip(),
    types=tuple(sorted(selected_types)),
    purdue_level=purdue_level,
    ics_stage=ics_stage,
    ransomware_only=ransomware_only,
    limit=RESULT_LIMIT,
)

total_matches = results.attrs.get("total_matches", len(results))

st.divider()

if results.empty:
    st.info("No matches. Try a broader keyword or fewer filters.")
    st.stop()

st.metric("Matches", f"{total_matches:,}")
if total_matches > RESULT_LIMIT:
    st.caption(
        f"Showing the first {RESULT_LIMIT:,} of {total_matches:,} real matches -- "
        "narrow the keyword or type filter to see the rest."
    )

st.dataframe(
    results.rename(
        columns={"id": "ID", "type": "Type", "label": "Label", "detail": "Detail"}
    ),
    width="stretch",
    hide_index=True,
)

st.divider()
st.subheader("Inspect a result")
st.caption(
    "Pick one match to see its full attrs and every real edge connected "
    "to it, each with its own resolvable source citation."
)

selected_id = st.selectbox("Node", options=results["id"].tolist())
if selected_id:
    detail = load_node_full(selected_id)
    if detail is None:
        st.warning("This node could not be re-loaded (it may have changed since the search ran).")
    else:
        with st.container(border=True):
            header_cols = st.columns([2, 1])
            header_cols[0].markdown(f"**{detail['label']}**  \n`{detail['id']}`")
            header_cols[1].markdown(f"Type: **{detail['type']}**")
            if detail["attrs"]:
                with st.expander("Full attrs"):
                    st.json(detail["attrs"])
            else:
                st.caption("(no attrs recorded on this node)")

        tab_out, tab_in = st.tabs(
            [
                f"Outgoing edges ({len(detail['outgoing'])})",
                f"Incoming edges ({len(detail['incoming'])})",
            ]
        )
        with tab_out:
            if not detail["outgoing"]:
                st.caption("No outgoing edges.")
            for e in detail["outgoing"]:
                cols = st.columns([1, 2, 2])
                cols[0].markdown(f"`{e['type']}`")
                cols[1].markdown(f"{e['dst_label']} ({e['dst_type']})")
                with cols[2]:
                    render_source_footer(e["source_id"])
        with tab_in:
            if not detail["incoming"]:
                st.caption("No incoming edges.")
            for e in detail["incoming"]:
                cols = st.columns([1, 2, 2])
                cols[0].markdown(f"`{e['type']}`")
                cols[1].markdown(f"{e['src_label']} ({e['src_type']})")
                with cols[2]:
                    render_source_footer(e["source_id"])
