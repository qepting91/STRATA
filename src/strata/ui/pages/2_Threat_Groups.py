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

Redesign note (this session): a group with many edges (e.g. SYLVANITE,
with 5 exploits + 6 tools + 2 techniques + 12 targets + 1 handoff, 26
rows total) previously rendered one full-width 3-column row per edge,
with most rows in the targets section citing the exact same corpus
source repeated over and over. That is real clutter, not real
information density. The fix applied here:
  - Targeting and techniques (low-information-per-item, frequently
    sharing one citation) are grouped by source_id and rendered as
    compact tag clusters, with the shared citation shown once per
    citation group, not once per tag.
  - Exploited CVEs and tools (richer, more heterogeneous data -- each
    row is a distinct CVE/tool, often with its own date/citation) are
    rendered as compact tables, not one full-width row per item.
  - st.tabs replaces one long undifferentiated vertical list, so an
    analyst can jump straight to the section they care about.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.components.stage_badge import render_stage_badge
from strata.ui.components.tag_cluster import render_tag_cluster
from strata.ui.data import (
    format_citation_label,
    load_group_detail,
    load_groups,
    load_technique_index,
    load_tool_index,
)

st.set_page_config(page_title="Threat Groups - STRATA", layout="wide")
st.title("Threat Groups")
st.caption(
    "Select a group for its full profile. Every claim below traces to a "
    "real source citation, shown once per shared citation for compact "
    "sections (targeting/techniques) and per row for richer tables "
    "(exploited CVEs/tools)."
)

groups_df = load_groups()

if groups_df.empty:
    st.warning("No group nodes found -- run `strata corpus load` first.")
    st.stop()

group_ids = sorted(groups_df["id"].tolist())
selected = st.selectbox("Select a threat group", group_ids)

row = groups_df[groups_df["id"] == selected].iloc[0]
# `row["attrs"] or {}` alone is not enough: a stub group (e.g.
# magnallium, referenced only via another group's hands_off_to edge, no
# full corpus entry of its own) has no attrs at all, and pandas
# represents that missing value as a bare float NaN in this mixed
# dict/None column, not Python None -- NaN is truthy, so `or {}` never
# fires and the first `.get()` call below raises AttributeError.
# (Found live while building the Analytical Frameworks page, which
# iterates every group including stubs and hit this immediately.)
raw_attrs = row["attrs"]
attrs = raw_attrs if isinstance(raw_attrs, dict) else {}

# --- Overview card -------------------------------------------------------
with st.container(border=True):
    st.subheader(row["label"])
    meta_cols = st.columns(4)
    meta_cols[0].metric("Naming org", attrs.get("naming_org") or "(stub)")
    with meta_cols[1]:
        st.caption("ICS kill-chain stage")
        render_stage_badge(attrs.get("ics_kill_chain_stage"))
    meta_cols[2].metric("Role", attrs.get("role") or "(unstated)")
    aliases = attrs.get("aliases") or []
    meta_cols[3].metric("Aliases", len(aliases))
    if aliases:
        st.caption("Aliases: " + ", ".join(aliases))

    st.caption(
        "Stage 1 = intrusion/espionage (reconnaissance through establishing a "
        "managed foothold). Stage 2 = ICS impact (developing, testing, and "
        "executing a capability against the physical process). Per Assante and "
        "Lee's ICS Cyber Kill Chain (SANS Institute, 2015), see the "
        "Analytical Frameworks page for the fuller explainer."
    )

detail = load_group_detail(selected)
outgoing = detail["outgoing"]
incoming_handoffs = detail["incoming_handoffs"]

if not outgoing and not incoming_handoffs:
    st.info(
        f"{selected!r} is a stub node (referenced only via another group's "
        "hands_off_to edge, no full corpus entry authored yet, see "
        "Collection Health for the list of thin/stub entries)."
    )
    st.stop()


def _grouped_targets_by_type(rows: list[dict]) -> list[tuple[str, dict[str, list[str]]]]:
    """Group targets edges by source_id, then by dst_type (sector/geo).

    Returns a list of (source_id, {"sector": [sorted labels], "geo": [...]})
    tuples. A group targeting 7 sectors and 5 geos sourced to one citation
    reads as two short comma-joined lines ("sector: ...", "geo: ...")
    rather than 12 separate pill tags -- real information density, not
    one-tag-per-item clutter.
    """
    groups: dict[str, dict[str, list[str]]] = {}
    for e in rows:
        by_type = groups.setdefault(e["source_id"], {})
        by_type.setdefault(e["dst_type"], []).append(e["dst_label"])
    for by_type in groups.values():
        for labels in by_type.values():
            labels.sort()
    return list(groups.items())


def _grouped_technique_rows(rows: list[dict]) -> list[tuple[str, list[dict]]]:
    """Group raw technique edge rows by source_id, preserving first-seen order.

    Keeps the raw edge dicts (not pre-joined label strings) so the caller
    can look each one up in the real ATT&CK technique index by `dst_id`.
    """
    groups: dict[str, list[dict]] = {}
    for e in rows:
        groups.setdefault(e["source_id"], []).append(e)
    return list(groups.items())


def _edge_table(rows: list[dict], item_col: str) -> pd.DataFrame:
    """Build a compact DataFrame for a richer, heterogeneous edge section."""
    return pd.DataFrame(
        [
            {
                item_col: e["dst_label"] or e["dst_id"],
                "First seen / note": e["note"] or "--",
                "Citation": format_citation_label(e["source_id"]),
            }
            for e in rows
        ]
    )


def _tool_table(rows: list[dict], tool_index: dict[str, dict]) -> pd.DataFrame:
    """Build the Tools table, adding a real MITRE ATT&CK software link.

    Each tool node's `attack_software_id`/`attack_software_url` (set by
    `enrich/attack_software.py`, an exact case-insensitive name/alias
    match against the real cached ATT&CK bundles) is looked up by the
    tool's own node id. Left blank -- never guessed -- when no real match
    exists.
    """
    records = []
    for e in rows:
        attrs = tool_index.get(e["dst_id"], {})
        software_id = attrs.get("attack_software_id")
        records.append(
            {
                "Tool": e["dst_label"] or e["dst_id"],
                "First seen / note": e["note"] or "--",
                "MITRE ATT&CK software": attrs.get("attack_software_url") if software_id else "",
                "Citation": format_citation_label(e["source_id"]),
            }
        )
    return pd.DataFrame(records)


targets = [e for e in outgoing if e["type"] == "targets"]
exploits = [e for e in outgoing if e["type"] == "exploits"]
tools = [e for e in outgoing if e["type"] == "uses"]
techniques = [e for e in outgoing if e["type"] == "implements"]
handoffs_out = [e for e in outgoing if e["type"] == "hands_off_to"]

tab_labels = [
    f"Targeting ({len(targets)})",
    f"Exploited CVEs ({len(exploits)})",
    f"Tools ({len(tools)})",
    f"Techniques ({len(techniques)})",
    f"Handoffs ({len(handoffs_out) + len(incoming_handoffs)})",
]
tab_targets, tab_exploits, tab_tools, tab_techniques, tab_handoffs = st.tabs(tab_labels)

with tab_targets:
    if not targets:
        st.caption("No targets edges for this group.")
    else:
        st.caption(
            "Targeted sectors and geographies, grouped by shared citation "
            "since most groups source their entire targeting claim to one "
            "publisher article. Each type (sector/geo) is one comma-joined "
            "line, not one tag per item."
        )
        for source_id, by_type in _grouped_targets_by_type(targets):
            for dst_type in sorted(by_type):
                st.markdown(f"**{dst_type}:** {', '.join(by_type[dst_type])}")
            render_source_footer(source_id)
            st.divider()

with tab_exploits:
    if not exploits:
        st.caption("No exploits edges for this group.")
    else:
        st.caption(
            "Each exploited CVE, with its corpus-cited first-seen date (if "
            "any) and per-row citation, shown as a table since this is "
            "richer, more heterogeneous data than a sector/geo tag."
        )
        st.dataframe(_edge_table(exploits, "CVE"), use_container_width=True, hide_index=True)

with tab_tools:
    if not tools:
        st.caption("No uses (tool) edges for this group.")
    else:
        st.caption(
            "Tools and malware families cited as used by this group. "
            "'MITRE ATT&CK software' links to that tool's real ATT&CK "
            "software page, where a corpus tool name exactly matches a "
            "real, non-deprecated ATT&CK malware/tool entry -- left blank "
            "(not guessed) where no such match exists."
        )
        tool_index = load_tool_index()
        st.dataframe(
            _tool_table(tools, tool_index),
            use_container_width=True,
            hide_index=True,
            column_config={
                "MITRE ATT&CK software": st.column_config.LinkColumn(display_text="View →")
            },
        )

with tab_techniques:
    if not techniques:
        st.caption("No implements (ATT&CK technique) edges for this group.")
    else:
        st.caption(
            "ATT&CK techniques, grouped by shared citation. Each tag links to "
            "its real MITRE ATT&CK technique page, where this graph has a "
            "matching cached technique node (populated by "
            "`strata collect --source attack`); its real MITRE description "
            "is listed below the tag cluster."
        )
        technique_index = load_technique_index()
        for source_id, group_rows in _grouped_technique_rows(techniques):
            attack_attrs = [technique_index.get(e["dst_id"], {}) for e in group_rows]
            labels = [
                f"{e['dst_id']}: {a['name']}" if a.get("name") else f"technique: {e['dst_id']}"
                for e, a in zip(group_rows, attack_attrs, strict=True)
            ]
            hrefs = [a.get("url") for a in attack_attrs]
            render_tag_cluster(labels, hrefs=hrefs)
            for label, a in zip(labels, attack_attrs, strict=True):
                if a.get("description"):
                    st.caption(f"**{label}**: {a['description']}")
            render_source_footer(source_id)
            st.divider()

with tab_handoffs:
    if not handoffs_out and not incoming_handoffs:
        st.caption("No handoff edges for this group.")
    else:
        if handoffs_out:
            st.markdown("**Hands off access to:**")
            for e in handoffs_out:
                cols = st.columns([3, 2])
                cols[0].markdown(e["dst_label"] or e["dst_id"])
                with cols[1]:
                    render_source_footer(e["source_id"])
        if incoming_handoffs:
            st.markdown("**Received handoffs (access received from):**")
            for e in incoming_handoffs:
                cols = st.columns([3, 2])
                cols[0].markdown(e["src_label"] or e["src_id"])
                with cols[1]:
                    render_source_footer(e["source_id"])
