"""Renders a compact cluster of small pill tags sharing one citation.

Built for the Threat Groups page redesign: a group's targeted sectors/
geos (and, more generally, any set of low-information same-citation
edges -- e.g. a group targeting 5 sectors and 7 geos, all sourced to one
corpus citation) do not need one full-width 3-column row per item with
the same footer repeated underneath every single one. Rendering them as
a wrapped cluster of small tags, with the shared citation shown once
underneath the whole cluster, is the actual fix for that clutter -- not
a data change, a display one.

Deliberately not interactive (no st.pills-style selection state) --
this is a read-only summary of what the graph already says, matching
verdict_badge.py/stage_badge.py's own st.markdown-based, non-interactive
rendering approach.
"""

from __future__ import annotations

import html

import streamlit as st

_TAG_STYLE = (
    "display:inline-block; background-color:#263238; color:#ffffff; "
    "font-size:0.85rem; font-weight:500; padding:0.25rem 0.7rem; "
    "border-radius:1rem; margin:0.15rem 0.3rem 0.15rem 0;"
)


def render_tag_cluster(labels: list[str], hrefs: list[str | None] | None = None) -> None:
    """Render `labels` as a wrapped cluster of small pill tags.

    Args:
        labels: Display strings, e.g. ["sector: electric", "geo: US"].
            Rendered in the given order, HTML-escaped.
        hrefs: Optional, parallel to `labels` -- a real external URL (e.g.
            a MITRE ATT&CK technique page) to make that one tag a link.
            `None` for any entry with no real URL to link to (e.g. a
            sector/geo tag, or a technique this graph has no cached ATT&CK
            node for) renders that tag as plain, non-clickable text --
            never a fabricated/guessed link.

    Deliberately does not accept a hover-tooltip `title=` per tag: real
    MITRE technique descriptions are long free-text that broke this HTML
    attribute in practice (found live -- Streamlit's markdown pass
    reprocesses parts of an attribute's text, corrupting the surrounding
    tag). Callers that want to show a technique's real description should
    render it as plain Markdown underneath the cluster instead.
    """
    if not labels:
        st.caption("(none)")
        return
    resolved_hrefs: list[str | None] = hrefs if hrefs is not None else [None] * len(labels)
    spans = []
    for label, href in zip(labels, resolved_hrefs, strict=True):
        escaped_label = html.escape(label)
        if href:
            spans.append(
                f'<a href="{html.escape(href)}" target="_blank" rel="noopener noreferrer" '
                f'style="{_TAG_STYLE} text-decoration:none;">{escaped_label}</a>'
            )
        else:
            spans.append(f'<span style="{_TAG_STYLE}">{escaped_label}</span>')
    st.markdown(f'<div style="line-height:2.4;">{"".join(spans)}</div>', unsafe_allow_html=True)
