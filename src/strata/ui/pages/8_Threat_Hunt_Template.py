"""Threat Hunt Template -- the generic, reusable hypothesis-hunting
methodology reference (Kyle O'Meara / Dragos's hypothesis-driven OT
threat-hunting practice), in this project's own words.

This is a well-known, generally-described professional CTI/OT hunting
methodology, cited by practice/name only -- not reproduced from any
specific copyrighted article, same discipline as the ICS Kill Chain/
Pyramid of Pain framing on the Analytical Frameworks page. No per-group
data lives here; it is the blank worksheet/reference form. Since this
project's whole UI is read-only (spec section 15.3), the worksheet
structure below is rendered as a labeled reference outline, not an
interactive fillable form -- see 9_Threat_Hunt_Examples.py for real,
populated instances of this same shape.
"""

from __future__ import annotations

import streamlit as st

st.set_page_config(page_title="Threat Hunt Template - STRATA", layout="wide")
st.title("Threat Hunt Template")
st.caption(
    "A generic, reusable hypothesis-hunting methodology reference -- the "
    "blank form. See Threat Hunt Examples for real, populated instances "
    "against STRATA's own corpus."
)

# --- Core philosophy -----------------------------------------------------
st.header("Core philosophy")
st.markdown(
    "Hypothesis-driven threat hunting is a discipline built around Kyle "
    "O'Meara / Dragos's hunting practice for OT environments, and it "
    "rests on a few non-negotiable principles:\n\n"
    "- **Success is proving or disproving the hypothesis, not finding an "
    "adversary.** A hunt that concludes \"no evidence found, hypothesis "
    "disproved\" is just as much a successful hunt as one that finds "
    "real adversary activity -- both are real, actionable conclusions.\n"
    "- **A visibility or logging gap discovered during a hunt is itself "
    "a valid, valuable finding.** \"We could not evaluate this hypothesis "
    "because we don't collect X\" is not a failed hunt -- it directly "
    "informs the collection/monitoring roadmap, and should be reported "
    "with the same weight as a proved/disproved conclusion.\n"
    "- **Hunts should be TTP-centric, not perishable-IOC-centric.** "
    "Indicators like hashes, IPs, and domains are cheap for an adversary "
    "to change; hunting for durable tactics/techniques/procedures forces "
    "an adversary to change how they operate, not just which artifact "
    "they use next -- see the Analytical Frameworks page's Pyramid of "
    "Pain section for the same principle applied to STRATA's own data.\n"
    "- **Every hunt needs a firm scope and a firm conclusion.** An "
    "open-ended hunt with no defined boundary or evaluation criteria "
    "never actually finishes -- scope (systems, time window, data "
    "sources) and an explicit PROVED/DISPROVED/INCONCLUSIVE endpoint are "
    "set before execution begins, not decided after the fact."
)

st.divider()

# --- 5-phase flow ---------------------------------------------------------
st.header("The 5-phase flow")

st.subheader("1. Hypothesis Generation")
st.markdown(
    "Driven by stakeholder **Priority Intelligence Requirements (PIRs)** "
    "-- what leadership actually needs to know -- and informed by the "
    "**5 intelligence streams**:\n\n"
    "1. First-party data (your own environment's logs, alerts, asset "
    "inventory)\n"
    "2. Information-sharing partnerships (ISACs, sector-specific sharing "
    "groups)\n"
    "3. Open-source intelligence (OSINT) -- public threat-group "
    "reporting, vendor blogs, researcher write-ups\n"
    "4. Paid commercial threat-intelligence (CTI) feeds\n"
    "5. Peer networks (informal analyst-to-analyst relationships)\n\n"
    "**Honest framing for STRATA specifically**: STRATA is itself one "
    "instance of the OSINT stream (item 3) -- a structured, provenance-"
    "tracked corpus built from public Dragos/vendor/press reporting. It "
    "is not, and does not claim to be, a replacement for the other 4 "
    "streams. A real hunt program needs first-party telemetry, sharing-"
    "partnership context, paid feeds, and peer input alongside anything "
    "STRATA's corpus can offer."
)

st.subheader("2. Data Source / Collection Management Framework (CMF) Mapping")
st.markdown(
    "For each step the hunt's execution plan requires, map it to a "
    "concrete data source and state plainly whether that source is "
    "actually collected today. This is where a hunt plan meets an "
    "environment's real telemetry inventory -- see the Visibility Gaps "
    "page's telemetry-requirement matrix for STRATA's own honest version "
    "of this mapping exercise."
)

st.subheader("3. Execution & Baseline Verification")
st.markdown(
    "Execute the hunt's queries/searches against the mapped data "
    "sources, with a particular focus on **living-off-the-land (LOTL) "
    "activity** -- legitimate administrative tools and protocols used for "
    "malicious purposes, which blend into a normal environment's "
    "baseline far more effectively than custom malware does. A hunt "
    "needs a real baseline of \"normal\" to recognize a deviation "
    "against, and a **firm timebox** so execution has a defined end, not "
    "an open-ended search."
)

st.subheader("4. Hypothesis Evaluation")
st.markdown(
    "Reach one of exactly three conclusions:\n\n"
    "- **PROVED** -- real evidence found supporting the hypothesis; hand "
    "off to Incident Response (IR) immediately.\n"
    "- **DISPROVED** -- the scoped search completed with no supporting "
    "evidence found; the null hypothesis stands.\n"
    "- **INCONCLUSIVE** -- the hunt could not be meaningfully evaluated "
    "(usually a real data/visibility gap, not a search that simply found "
    "nothing) -- report the specific gap, don't force a PROVED/DISPROVED "
    "call the data can't support. This is the honest, and often most "
    "common, real outcome when working from open-source/aggregated "
    "intelligence rather than a defender's own first-party telemetry -- "
    "see the Visibility Gaps and Collection Health pages for exactly "
    "which telemetry this project itself does and doesn't have."
)

st.subheader("5. Multi-Tiered Reporting")
st.markdown(
    "Report the outcome to three distinct audiences, each needing a "
    "different level of detail:\n\n"
    "- **Strategic** -- leadership-level: risk framing, business impact, "
    "no technical detail required.\n"
    "- **Operational** -- program-level: what was hunted, what it means "
    "for the broader detection/collection roadmap.\n"
    "- **Tactical** -- analyst-level: the specific queries, data "
    "sources, and evidence (or lack of it) an incident responder or "
    "fellow hunter would need to reproduce or extend the work."
)

st.divider()

# --- Standard hypothesis formula -----------------------------------------
st.header("Standard hypothesis formula")
st.code(
    "[Adversary / cluster]  +  [TTP / vector]  +  [target system]  +  [network enclave]\n\n"
    "Example shape (illustrative, not a real filled hypothesis):\n"
    "  \"<GROUP> is using <technique/tool> against <system type> "
    "within <network segment>.\"",
    language="text",
)

st.divider()

# --- Blank worksheet structure --------------------------------------------
st.header("Blank worksheet structure")
st.caption(
    "The same shape STRATA's own hunt-hypothesis data model captures "
    "(see normalize/hunt_hypothesis_models.py) -- rendered here as an "
    "empty reference form, not an interactive fillable one (this UI is "
    "read-only, per spec section 15.3)."
)
st.code(
    """group_id: <threat-group id>

hypothesis_statement: >
  <Adversary/cluster> + <TTP/vector> + <target system> + <network enclave>

pir_reference: >
  Illustrative PIR: <the stakeholder priority question this hunt answers>

cmf_notes:
  - hunt_step: <a concrete step in the execution plan>
    strata_coverage: >
      <modeled directly / partially modeled / NOT modeled -- and why>
  - hunt_step: <next step>
    strata_coverage: <...>

outcome_criteria:
  proved: >
    <what concrete evidence would prove the hypothesis>
  disproved: >
    <what a completed, clean search looks like>
  inconclusive: >
    <what specific data/visibility gap would force this conclusion>
""",
    language="yaml",
)

st.divider()
st.subheader("Methodology & references")
st.markdown(
    "- **Hypothesis-driven OT threat hunting** (Kyle O'Meara / Dragos "
    "hunting practice) -- grounds this page's 5-phase flow, the 5 "
    "intelligence streams, and the PROVED/DISPROVED/INCONCLUSIVE "
    "evaluation model. Described here in this project's own words, "
    "cited by practice/name only.\n"
    "- See **Analytical Frameworks** for the Pyramid of Pain framing "
    "this page's \"TTP-centric, not IOC-centric\" principle builds on.\n"
    "- See **Visibility Gaps** for STRATA's own real telemetry-"
    "requirement matrix, the concrete analogue of this page's Phase 2 "
    "CMF mapping."
)
