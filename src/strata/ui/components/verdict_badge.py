"""Renders a hunt verdict (SUPPORTED/REFUTED/INSUFFICIENT) with equal
visual prominence for every state.

Direct product requirement, not just data honesty: spec section 15.2
states refuted cards must be "styled with equal weight to supported
ones, deliberately" -- a board that is all green is evidence of a
curated dataset, not a good analyst (spec section 7.3). No verdict here
is dimmed, greyed out, or otherwise visually de-emphasized relative to
the others; each gets its own solid, high-contrast color and an equally
bold label.
"""

from __future__ import annotations

import streamlit as st

_VERDICT_STYLE = {
    "SUPPORTED": {"bg": "#1b5e20", "fg": "#ffffff", "label": "SUPPORTED"},
    "REFUTED": {"bg": "#b71c1c", "fg": "#ffffff", "label": "REFUTED"},
    "INSUFFICIENT": {"bg": "#7a4f01", "fg": "#ffffff", "label": "INSUFFICIENT"},
}


def render_verdict_badge(verdict: str) -> None:
    """Render one verdict badge as a colored block via st.markdown.

    Args:
        verdict: One of "SUPPORTED", "REFUTED", "INSUFFICIENT". Any other
            value renders a neutral grey badge rather than raising, so a
            future verdict state doesn't crash the page.
    """
    style = _VERDICT_STYLE.get(
        verdict, {"bg": "#37474f", "fg": "#ffffff", "label": verdict}
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
        ">{style['label']}</div>""",
        unsafe_allow_html=True,
    )


def verdict_counts(verdicts: list[str]) -> dict[str, int]:
    """Return a mapping of verdict -> count, for a summary strip.

    A tiny pure helper (no Streamlit calls) so it's trivially unit-
    testable without AppTest.
    """
    counts: dict[str, int] = {"SUPPORTED": 0, "REFUTED": 0, "INSUFFICIENT": 0}
    for v in verdicts:
        counts[v] = counts.get(v, 0) + 1
    return counts
