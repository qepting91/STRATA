"""STRATA Streamlit UI entrypoint (spec section 15).

Launched via `strata ui` (see cli.py, which shells out to
`streamlit run <this file>`), or directly via
`streamlit run src/strata/ui/app.py` in a dev shell.

This file itself does not touch the database -- it is a landing page plus
Streamlit's automatic multipage navigation (pages/1_Hunt_Board.py etc, per
spec section 15.2's layout). All reads happen in ui/data.py via a
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
happen via the `strata` CLI (`strata collect`, `strata build`,
`strata hunt run`).

Use the sidebar to navigate:

- **Hunt Board** -- all 10 curated hunts with their real verdicts
  (SUPPORTED / REFUTED / INSUFFICIENT), shown with equal prominence.
- **Threat Groups** -- pick a group, see its targets/exploits/tools/
  techniques/handoffs, each with an inline source citation.
- **Weaponization Timeline** -- the real (currently small) set of
  disclosure-to-PoC / PoC-to-KEV interval metrics.
- **Protocol CVEs** -- the 3 real ICS-protocol-involving CVEs, plus the
  classifier's own measured precision/recall from a 200-CVE validation
  set.
- **Visibility Gaps** -- the telemetry requirement matrix, sorted by
  difficulty.
- **Collection Health** -- per-source counts/last-fetch times and known
  gaps (the honest page).
        """
    )

    db_path = get_db_path()
    st.info(f"Database: `{db_path}`")


if __name__ == "__main__":
    main()
