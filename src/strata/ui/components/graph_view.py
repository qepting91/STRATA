"""NetworkX -> pyvis rendering for the group handoff model (spec section 15.5).

Pyvis defaults to a CDN for vis.js assets; cdn_resources="local" ships
them from the installed pyvis package instead, so nothing in this
component ever reaches out to the network -- consistent with the whole
project's egress-allowlist model (a CDN fetch from the UI would be
exactly the kind of hole the allowlist in the collectors is designed to
prevent, per spec section 15.1's own reasoning).

Rendered to a local HTML string and embedded via st.iframe -- no temp
file server, no port beyond Streamlit's own. The HTML embedded here is
always self-generated from our own graph data (never user/external
input), so st.iframe's untrusted-HTML warning does not apply.
"""

from __future__ import annotations

import networkx as nx
import streamlit as st
from pyvis.network import Network

_TYPE_COLORS = {
    "group": "#1565c0",
    "tool": "#6a1b9a",
    "vuln": "#b71c1c",
    "product": "#2e7d32",
    "technique": "#ef6c00",
    "protocol": "#00838f",
}


def render_graph(graph: nx.DiGraph, height: str = "500px") -> None:
    """Render a NetworkX DiGraph as an interactive pyvis network.

    Args:
        graph: A networkx.DiGraph whose nodes optionally carry a "type"
            attribute (used for coloring) and whose edges optionally
            carry a "type" attribute (used as the edge label).
        height: CSS height string for the embedded iframe.
    """
    if graph.number_of_nodes() == 0:
        st.info("No nodes to render for this selection.")
        return

    net = Network(
        height=height,
        width="100%",
        directed=True,
        notebook=False,
        cdn_resources="local",
    )

    for node_id, attrs in graph.nodes(data=True):
        node_type = attrs.get("type", "unknown")
        color = _TYPE_COLORS.get(node_type, "#616161")
        net.add_node(node_id, label=str(node_id), title=node_type, color=color)

    for src, dst, attrs in graph.edges(data=True):
        edge_type = attrs.get("type", "")
        net.add_edge(src, dst, title=edge_type, label=edge_type)

    html = net.generate_html(notebook=False)
    st.iframe(html, height=int(height.replace("px", "")) + 50)
