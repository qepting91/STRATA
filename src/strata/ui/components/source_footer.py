"""Renders the provenance citation for any displayed claim.

Given a source_id (either a corpus citation id like "S-0001", or a
collector-written source row id like "nvd-CVE-2023-46805"), looks up and
renders publisher/URL/retrieved-or-fetched date -- the concrete mechanism
behind this project's central claim that every edge is traceable to a
real, publicly linkable document.
"""

from __future__ import annotations

import streamlit as st

from strata.ui import data as ui_data


def render_source_footer(source_id: str | None) -> None:
    """Render a small caption line citing source_id's publisher/URL/date.

    Args:
        source_id: A source/citation id, or None (renders nothing useful
            -- some edges genuinely have no per-row source, e.g. KEV's
            single shared per-catalog-fetch source).
    """
    if not source_id:
        st.caption("source: (none recorded)")
        return

    citations = ui_data.load_citations()
    citation = citations.get(source_id)
    if citation is not None:
        publisher = citation.get("publisher", "unknown publisher")
        url = citation.get("url", "")
        retrieved = citation.get("retrieved", "unknown date")
        st.caption(f"source: {publisher} -- [{url}]({url}) (retrieved {retrieved})")
        return

    source_row = ui_data.load_source(source_id)
    if source_row is not None:
        name = source_row.get("name", "unknown source")
        url = source_row.get("url") or ""
        fetched_at = source_row.get("fetched_at", "unknown date")
        if url:
            st.caption(f"source: {name} -- [{url}]({url}) (fetched {fetched_at})")
        else:
            st.caption(f"source: {name} (fetched {fetched_at})")
        return

    st.caption(f"source: {source_id} (not found in citations.yaml or source table)")
