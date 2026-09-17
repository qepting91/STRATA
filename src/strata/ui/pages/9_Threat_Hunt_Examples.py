"""Threat Hunt Examples -- populated hunt-hypothesis worksheets for real
threat groups, following the shape described on the Threat Hunt Template
page.

Real target sectors/geos/tools/techniques/handoffs are pulled live from
the graph (reusing 2_Threat_Groups.py's own load_group_detail/
load_groups loaders, not a duplicate query) with the same inline-
citation treatment via source_footer.py. The hunt-hypothesis analytical
fields (hypothesis_statement/pir_reference/cmf_notes/outcome_criteria)
come from corpus/hunt_hypotheses/<group>.yaml, read read-only via
ui/data.py::load_hunt_hypotheses -- never written into the graph.

corpus/hunt_hypotheses/ is empty until the 3 real example files
(azurite/voltzite/pyroxene) are authored directly, given the same
citation-accuracy stakes as every other corpus file in this project --
this page handles that "no example yet" state with a plain st.info
rather than crashing or hiding the rest of the page.
"""

from __future__ import annotations

import streamlit as st

from strata.ui.components.source_footer import render_source_footer
from strata.ui.components.stage_badge import render_stage_badge
from strata.ui.data import load_group_detail, load_groups, load_hunt_hypotheses

st.set_page_config(page_title="Threat Hunt Examples - STRATA", layout="wide")
st.title("Threat Hunt Examples")
st.caption(
    "Populated hunt-hypothesis worksheets: real per-group graph data "
    "plus this project's own analytical judgment, every field traceable "
    "to a real citation. See Threat Hunt Template for the generic, "
    "blank version of this same shape."
)

hypotheses = load_hunt_hypotheses()

if not hypotheses:
    st.info(
        "No hunt-hypothesis example files exist yet in "
        "`corpus/hunt_hypotheses/`. These are authored directly (same "
        "citation-accuracy discipline as `corpus/groups/*.yaml`), so "
        "this page has nothing populated to show until at least one "
        "exists -- see the Threat Hunt Template page for the generic, "
        "reusable methodology reference in the meantime."
    )
    st.stop()

group_ids = sorted(hypotheses.keys())
selected = st.selectbox("Select a threat-hunt example group", group_ids)
hypothesis = hypotheses[selected]

groups_df = load_groups()
matching = groups_df[groups_df["id"] == selected]

st.header(selected)

if matching.empty:
    st.warning(
        f"{selected!r} has a hunt-hypothesis file but no matching group "
        "node in the graph -- run `strata corpus load` if this group's "
        "own corpus/groups/*.yaml file is expected to exist."
    )
else:
    row = matching.iloc[0]
    raw_attrs = row["attrs"]
    attrs = raw_attrs if isinstance(raw_attrs, dict) else {}

    meta_cols = st.columns(3)
    meta_cols[0].metric("Naming org", attrs.get("naming_org") or "(stub)")
    with meta_cols[1]:
        st.caption("ICS kill-chain stage")
        render_stage_badge(attrs.get("ics_kill_chain_stage"))
    meta_cols[2].metric("Role", attrs.get("role") or "(unstated)")

    detail = load_group_detail(selected)
    outgoing = detail["outgoing"]

    _EDGE_LABELS = {
        "targets": "Targeted sectors / geos",
        "exploits": "Exploited CVEs",
        "uses": "Tools",
        "implements": "ATT&CK techniques",
        "hands_off_to": "Hands off access to",
    }
    for edge_type, label in _EDGE_LABELS.items():
        rows = [e for e in outgoing if e["type"] == edge_type]
        if not rows:
            continue
        st.markdown(f"#### {label}")
        for e in rows:
            cols = st.columns([1, 3, 2])
            cols[0].markdown(f"**{e['dst_type']}**")
            cols[1].markdown(e["dst_label"] or e["dst_id"])
            with cols[2]:
                render_source_footer(e["source_id"])

st.divider()

# --- Hunt hypothesis worksheet -------------------------------------------
st.subheader("Hunt hypothesis")
st.markdown(hypothesis.hypothesis_statement)
render_source_footer(hypothesis.src)

st.subheader("Priority Intelligence Requirement")
st.markdown(hypothesis.pir_reference)

st.subheader("Collection Management Framework (CMF) notes")


def _coverage_flag(strata_coverage: str) -> str:
    """Return a short honesty-flag icon prefix for a CMF coverage string.

    Purely textual heuristic over this project's own authored
    strata_coverage prose (which always states one of these three
    postures explicitly, per hunt_hypothesis_models.py's own docstring
    convention) -- not a semantic classifier.
    """
    lowered = strata_coverage.lower()
    if "not modeled" in lowered:
        return "\U0001f534 NOT MODELED"  # red circle
    if "partially modeled" in lowered:
        return "\U0001f7e1 PARTIALLY MODELED"  # yellow circle
    if "modeled directly" in lowered or "modeled" in lowered:
        return "\U0001f7e2 MODELED"  # green circle
    return "⚪ UNSTATED"  # white circle


for note in hypothesis.cmf_notes:
    cols = st.columns([3, 2, 3])
    cols[0].markdown(f"**{note.hunt_step}**")
    cols[1].markdown(_coverage_flag(note.strata_coverage))
    with cols[2]:
        st.markdown(note.strata_coverage)
        if note.src:
            render_source_footer(note.src)

st.subheader("Outcome criteria")
oc = hypothesis.outcome_criteria
oc_cols = st.columns(3)
oc_cols[0].markdown("**PROVED**")
oc_cols[0].markdown(oc.proved)
oc_cols[1].markdown("**DISPROVED**")
oc_cols[1].markdown(oc.disproved)
oc_cols[2].markdown("**INCONCLUSIVE**")
oc_cols[2].markdown(oc.inconclusive)
