"""STRATA Streamlit UI entrypoint (spec section 15).

Launched via `strata ui` (see cli.py, which shells out to
`streamlit run <this file>`), or directly via
`streamlit run src/strata/ui/app.py` in a dev shell.

This file itself does not touch the database -- it is a landing page plus
Streamlit's automatic multipage navigation (pages/2_Threat_Groups.py etc).
All reads happen in ui/data.py via a
mode=ro connection; no writes, no ingest triggers, no shell-outs happen
anywhere in this package. The CLI remains the only thing that mutates
state.
"""

from __future__ import annotations

import streamlit as st

from strata.ui.data import get_db_path

st.set_page_config(
    page_title="STRATA - OT/ICS Threat Capability Tracker",
    page_icon=":mag:",
    layout="wide",
)


def main() -> None:
    """Render the landing page. Pages/ are auto-discovered by Streamlit."""
    st.title("STRATA")
    st.caption("Local-only OT/ICS threat-capability tracking -- read-only dashboard")

    st.markdown(
        """
This is a **read-only** view over the local STRATA graph database. Every
page connects with a `mode=ro` SQLite URI -- this process cannot write to
the database under any circumstance. Ingestion and enrichment only ever
happen via the `strata` CLI (`strata collect`, `strata build`).

Use the sidebar to navigate:

- **Threat Groups** -- pick a group, see its targets/exploits/tools/
  techniques/handoffs, each with an inline source citation and a real
  MITRE ATT&CK technique/software link where one exists.
- **Weaponization Timeline** -- disclosure-to-PoC / PoC-to-KEV / patch-
  before-KEV interval metrics, computed from the signal collectors and
  KEV/NVD/CSAF dates below.
- **Protocol CVEs** -- CVEs whose NVD description or CSAF product-tree
  text names a specific ICS protocol, plus the classifier's own measured
  precision/recall from a 200-CVE validation set.
- **Visibility Gaps** -- the telemetry requirement matrix, sorted by
  difficulty.
- **Collection Health** -- per-source counts/last-fetch times and known
  gaps (the honest page -- the live, current numbers referenced only
  qualitatively below live there, not hardcoded into this page).
- **Analytical Frameworks** -- ICS Cyber Kill Chain, Purdue level, and
  Pyramid of Pain framing applied to this project's own real data.
- **Threat Hunt Template / Examples** -- the reusable hypothesis-driven
  hunting worksheet, and real worked examples against this graph's data.
        """
    )

    st.divider()
    st.subheader("Data sources")
    st.caption(
        "Every fact anywhere in STRATA traces back to one of the sources "
        "below -- a fetched public feed, or a hand-curated, individually "
        "cited corpus file. Full licensing/cadence/scope-decision detail "
        "for each lives in `SOURCES.md`; this is the short version, framed "
        "around what each source actually feeds into in this app."
    )

    with st.expander("CISA KEV -- Known Exploited Vulnerabilities catalog"):
        st.markdown(
            "**Collects:** `cveID`, vendor/product, `dateAdded` (the date "
            "CISA confirmed active exploitation), `knownRansomwareCampaignUse`.\n\n"
            "**Feeds:** seeds the graph's `vuln` nodes; `dateAdded` is the "
            "`t_kev` anchor for every Weaponization Timeline interval "
            "metric; `knownRansomwareCampaignUse` flags ransomware-linked "
            "CVEs, cross-referenceable against real `involves` protocol "
            "edges on the Protocol CVEs page."
        )

    with st.expander("CISA CSAF -- ICS/IT/vulnerability advisories"):
        st.markdown(
            "**Collects:** CSAF 2.0 advisory documents -- tracking id, "
            "`initial_release_date`, `product_tree`, per-CVE CVSS/CWE.\n\n"
            "**Feeds:** `advisory`/`vuln` nodes and `describes` edges; the "
            "product-tree text is one of the Protocol CVEs classifier's "
            "two real inputs (alongside NVD description text); "
            "`initial_release_date` is a real disclosure-date source for "
            "the Weaponization Timeline."
        )

    with st.expander("NVD -- CVE enrichment"):
        st.markdown(
            "**Collects:** CVSS v3.1 base score/vector, CWE id(s), CPE "
            "`configurations` (-> `product`/`vendor` nodes), and the "
            "English-language CVE description.\n\n"
            "**Feeds:** the Purdue-level mapping (via the CPE-derived "
            "product/vendor nodes) and Protocol CVEs' primary classifier "
            "input text."
        )

    with st.expander("MITRE ATT&CK -- enterprise + ICS techniques"):
        st.markdown(
            "**Collects:** every real, non-deprecated ATT&CK technique "
            "(id, name, description, tactics) and software/malware entry "
            "(id, name, aliases), from the same STIX bundles MITRE "
            "itself publishes.\n\n"
            "**Feeds:** the real technique name/description/link shown "
            "next to every group's cited technique on the Threat Groups "
            "page, and the real (exact-name-match, never guessed) MITRE "
            "ATT&CK software cross-reference shown next to matching tools."
        )

    with st.expander("FIRST.org EPSS -- exploit prediction scores"):
        st.markdown(
            "**Collects:** the `epss` and `epss_percentile` score for "
            "every CVE already in the graph, as of the current date.\n\n"
            "**Feeds:** written as `metric_observation` rows -- collected "
            "but not yet surfaced in a dedicated UI page (an honest, "
            "documented gap, not a hidden one; see Collection Health)."
        )

    with st.expander("PoC-in-GitHub / Exploit-DB / Nuclei / Metasploit -- weaponization signals"):
        st.markdown(
            "**Collects:** for each, a bounded, real sample of "
            "\"this CVE was referenced here, on this date\" facts -- a "
            "public PoC repo commit, an Exploit-DB entry, a nuclei "
            "detection template, or a Metasploit exploit module -- "
            "written to a separate `signal` table, not the node/edge "
            "graph.\n\n"
            "**Feeds:** the disclosure-to-PoC and PoC-to-KEV interval "
            "metrics on the Weaponization Timeline page."
        )

    with st.expander("Siemens ProductCERT / Schneider Electric CPCERT -- vendor PSIRT CSAF"):
        st.markdown(
            "**Collects:** each vendor's own CSAF 2.0 security advisories "
            "-- real, vendor-native `initial_release_date` values, "
            "distinct from KEV/NVD/CISA-CSAF's US-government-aggregated "
            "dates.\n\n"
            "**Feeds:** the only real per-vendor patch-latency data in "
            "this graph -- currently thin (most fetched advisories are "
            "for CVEs NVD/KEV haven't caught up on yet), reported "
            "honestly on Collection Health rather than glossed over."
        )

    with st.expander("Corpus -- hand-curated, individually cited threat-group profiles"):
        st.markdown(
            "**Collects:** not fetched by a collector -- each "
            "`corpus/groups/<id>.yaml` file is authored directly against "
            "a real public source (overwhelmingly Dragos's own public "
            "`dragos.com/threat/<group>` pages, plus vendor/press "
            "reporting for specific CVE-exploitation claims), with every "
            "single fact -- each sector, tool, technique, alias -- citing "
            "its own entry in `corpus/citations.yaml`.\n\n"
            "**Feeds:** the entire Threat Groups page; the Analytical "
            "Frameworks page's ICS Kill Chain stage badges and Pyramid of "
            "Pain mapping; and the Threat Hunt Template/Examples pages."
        )

    db_path = get_db_path()
    st.info(f"Database: `{db_path}`")


if __name__ == "__main__":
    main()
