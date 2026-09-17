"""Analytical Frameworks -- ICS Cyber Kill Chain, Purdue-level attack
surface, and the Pyramid of Pain, all grounded in this project's own
real, collected data.

This page cites two documents by name (title/author/year) but never
serves, links, or reproduces either one: the SANS/Assante & Lee ICS
Cyber Kill Chain paper's own cover page states "Reposting is not
permitted without express written permission," and `.streamlit/
config.toml` keeps `enableStaticServing=false` regardless. Every
explainer below is this project's own summary in its own words, not a
quotation.
"""

from __future__ import annotations

import streamlit as st

from strata.ui.components.stage_badge import render_stage_badge
from strata.ui.data import load_groups, load_purdue_cve_mass, load_pyramid_of_pain_counts

st.set_page_config(page_title="Analytical Frameworks - STRATA", layout="wide")
st.title("Analytical Frameworks")
st.caption(
    "How this project's own collected data maps onto three standard, "
    "well-known CTI/ICS models -- own-words framing, cited by name."
)

# --- A. ICS Cyber Kill Chain -------------------------------------------
st.header("1. ICS Cyber Kill Chain")
st.markdown(
    "The Industrial Control System Cyber Kill Chain (Michael Assante and "
    "Robert M. Lee, SANS Institute, 2015) splits an ICS-focused intrusion "
    "into two stages. **Stage 1** covers everything from initial "
    "reconnaissance through establishing a reliable, managed foothold in "
    "a target environment -- it is fundamentally an intrusion/espionage "
    "phase, and a group can operate here indefinitely without ever "
    "touching the physical process. **Stage 2** is the ICS-impact phase: "
    "developing, testing, and finally executing a capability that "
    "actually manipulates or disrupts the physical process being "
    "controlled. Stage 2 is rarer, harder, and far more consequential -- "
    "but Stage 1 is where the vast majority of real-world access actually "
    "gets established, which is exactly why this project tracks both "
    "stages rather than only the more dramatic one."
)

groups_df = load_groups()
if groups_df.empty:
    st.info("No group nodes found -- run `strata corpus load` first.")
else:
    st.subheader("Corrected, per-group stage assignment")
    st.caption(
        "AZURITE and PYROXENE were corrected from Stage 1 to Stage 2 this "
        "session after reading the Dragos 2026 OT/ICS Cybersecurity Year "
        "in Review directly -- its own \"About\" sections state both "
        "groups explicitly as Stage 2 adversaries, a stronger primary "
        "source than the earlier web-search pass this corpus was "
        "originally authored from."
    )
    for _, row in groups_df.sort_values("id").iterrows():
        # Stub groups (referenced only via another group's hands_off_to
        # edge, no full corpus entry of their own -- e.g. magnallium)
        # have no attrs at all. pandas represents that missing value as
        # a bare float NaN in this mixed dict/None column, not Python
        # None, so `row["attrs"] or {}` (which works fine for a real
        # None) doesn't catch it -- NaN is truthy.
        raw_attrs = row["attrs"]
        attrs = raw_attrs if isinstance(raw_attrs, dict) else {}
        cols = st.columns([2, 1, 4])
        cols[0].markdown(f"**{row['label']}**")
        with cols[1]:
            render_stage_badge(attrs.get("ics_kill_chain_stage"))
        cols[2].caption(attrs.get("role") or "(role unstated)")

st.divider()

# --- B. Purdue-level attack surface -------------------------------------
st.header("2. Purdue-level attack surface")
st.markdown(
    "The Purdue Enterprise Reference Architecture layers an industrial "
    "environment from Level 0 (physical process) up through Level 5 "
    "(enterprise IT), with Level 3.5 as the IT/OT demilitarized zone -- "
    "VPN gateways, jump hosts, historian replication servers, and "
    "similar edge devices. The chart below is the real, live count of "
    "distinct CVEs (`affects` edges) reaching Purdue-classified products "
    "in this corpus, grouped by level."
)

purdue_df = load_purdue_cve_mass()
if purdue_df.empty:
    st.info("No Purdue-classified products with an affects edge found.")
else:
    chart_df = purdue_df.set_index("purdue_level")
    st.bar_chart(chart_df["cve_mass"])
    st.dataframe(
        purdue_df.rename(columns={"purdue_level": "Purdue level", "cve_mass": "Distinct CVEs"}),
        use_container_width=True,
        hide_index=True,
    )

st.markdown(
    "**Why 3.5 matters more than Level 1 PLC mystique:** headline "
    "incidents (Stuxnet, TRITON, INDUSTROYER) center attention on "
    "field-device-level (Level 1) compromise, but the real, measurable "
    "CVE mass in this corpus concentrates at the boundary layer -- "
    "internet-facing edge devices are simply exposed to far more of the "
    "CVE pipeline than a PLC that has no route to the internet at all. "
    "Monitoring and patch-prioritization investment should follow where "
    "the CVEs actually are, not where the most cinematic incident "
    "happened to occur."
)

st.markdown(
    "**External validation -- the Dragos 2026 report's own Now/Next/"
    "Never split:** the same report splits its own tracked OT "
    "vulnerabilities into three buckets -- roughly 3% \"Now\" (needing "
    "immediate action; actively or imminently exploited), 71% \"Next\" "
    "(mitigable through network segmentation or other compensating "
    "controls, not urgent patching), and 27% \"Never\" (low enough value "
    "to an adversary that remediation effort is better spent elsewhere). "
    "Independently of this project's own data, that split makes the same "
    "underlying point the Purdue-level chart above and the adversary-"
    "consensus scoring already argue: OT vulnerability management is "
    "fundamentally a triage problem best driven by real, observed "
    "adversary behavior -- not a patch-everything-by-raw-CVSS-score "
    "problem."
)

st.divider()

# --- C. Pyramid of Pain --------------------------------------------------
st.header("3. Pyramid of Pain")
st.markdown(
    "David Bianco's Pyramid of Pain ranks indicator types by how much "
    "cost/pain it imposes on an adversary when a defender detects and "
    "denies that indicator -- from trivially-replaceable hash values at "
    "the bottom, up through IP addresses, domain names, network/host "
    "artifacts, tools, and finally TTPs (tactics, techniques, and "
    "procedures) at the top, which force an adversary to change how they "
    "operate, not just which file or server they use next."
)

pyramid = load_pyramid_of_pain_counts()
_PYRAMID_ROWS = [
    (
        "TTPs",
        f"{pyramid['n_techniques']} ATT&CK technique nodes, "
        f"{pyramid['n_implements_edges']} implements edges",
        "Top strength -- forces an adversary to change tradecraft, not just infrastructure.",
    ),
    (
        "Tools",
        f"{pyramid['n_tools']} tool nodes, {pyramid['n_uses_edges']} uses edges",
        "Real strength -- named, cited malware/webshell/tunnel families per group.",
    ),
    (
        "Network/Host Artifacts",
        f"{pyramid['network_host_artifacts']} signal `ref` URLs (PoC/exploit-DB links)",
        "Thin -- these are pointers to public PoC repos, not classic host/network artifacts.",
    ),
    ("Domain Names", "0 -- none collected", "Deliberate design boundary, not a gap."),
    ("IP Addresses", "0 -- none collected", "Deliberate design boundary, not a gap."),
    (
        "Hash Values",
        "0 -- none collected, and never will be",
        "This project's own no-malware-sample-handling policy (SECURITY.md) "
        "means it never ingests or stores malware samples, so there is "
        "never a hash to compute.",
    ),
]
for layer, real_data, note in reversed(_PYRAMID_ROWS):
    cols = st.columns([2, 3, 4])
    cols[0].markdown(f"**{layer}**")
    cols[1].markdown(real_data)
    cols[2].caption(note)

st.markdown(
    "STRATA deliberately operates at the top of the pyramid -- tools and "
    "TTPs -- which is exactly where an adversary has to invest the most "
    "effort to change if a defender disrupts them. This is consistent "
    "with the SANS ICS Cyber Kill Chain paper's own point (in this "
    "project's own words, not a quotation) that focusing purely on "
    "malware signatures or low-level IOCs misses the campaign-level "
    "picture an ICS defender actually needs."
)

st.divider()

# --- D. Methodology & references ----------------------------------------
st.header("4. Methodology & references")
st.markdown(
    "- **The Industrial Control System Cyber Kill Chain** (Michael "
    "Assante and Robert M. Lee, SANS Institute, 2015) -- grounds this "
    "page's Stage 1/Stage 2 framing and the per-group stage badges "
    "shown above and on the Threat Groups page. Cited by name only; not "
    "reproduced or served, per the paper's own copyright notice.\n"
    "- **9th Annual Dragos OT/ICS Cybersecurity Year in Review** "
    "(Dragos, Feb 2026) -- grounds the AZURITE/PYROXENE stage "
    "corrections, the Godzilla/frp cross-group tool citations, and the "
    "Now/Next/Never vulnerability-triage cross-reference above. Cited "
    "by name only; not served as a downloadable file."
)
