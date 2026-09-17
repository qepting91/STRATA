"""Renders an ICS Cyber Kill Chain stage (1 or 2) with equal visual weight.

Stage 1 and Stage 2 (Assante & Lee, "The Industrial Control System Cyber
Kill Chain," SANS Institute, 2015) are different adversary *roles*, not a
better/worse ranking -- an intrusion/espionage group (Stage 1) is not a
"lesser" finding than an ICS-impact group (Stage 2). This mirrors
verdict_badge.py's own equal-prominence styling philosophy: neither state
gets a warmer/cooler or larger/smaller treatment than the other.
"""

from __future__ import annotations

import streamlit as st

_STAGE_STYLE = {
    1: {
        "bg": "#0d47a1",
        "fg": "#ffffff",
        "label": "STAGE 1",
        "caption": "Intrusion / espionage",
    },
    2: {
        "bg": "#4a148c",
        "fg": "#ffffff",
        "label": "STAGE 2",
        "caption": "ICS impact",
    },
}


def render_stage_badge(stage: int | float | str | None) -> None:
    """Render one ICS Cyber Kill Chain stage badge via st.markdown.

    Args:
        stage: The group's ``ics_kill_chain_stage`` attr -- expected to be
            ``1`` or ``2``. Any other value (including ``None``/unstated)
            renders a neutral grey "STAGE ?" badge rather than raising, so
            a stub/unclassified group doesn't crash the page.
    """
    try:
        key = int(stage)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        key = None
    style = _STAGE_STYLE.get(
        key, {"bg": "#37474f", "fg": "#ffffff", "label": "STAGE ?", "caption": "unstated"}
    )
    st.markdown(
        f"""<div style="
            display:inline-block;
            background-color:{style['bg']};
            color:{style['fg']};
            font-weight:700;
            font-size:0.95rem;
            padding:0.3rem 0.9rem;
            border-radius:0.4rem;
            letter-spacing:0.05em;
        ">{style['label']}</div>
        <div style="font-size:0.8rem; color:{style['bg']}; margin-top:0.15rem;">
            {style['caption']}
        </div>""",
        unsafe_allow_html=True,
    )
