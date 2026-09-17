"""Static handoff-model graph render (spec section 8.3): the single image
that explains the project in five seconds -- group nodes + hands_off_to
edges only, rendered to Graphviz DOT format, plus a PNG if the `dot`
binary is actually available on this machine.

Deliberately does not add a `graphviz`/`pydot` Python binding dependency:
the DOT text this module needs is simple enough to emit by hand, and
`shutil.which("dot")` + `subprocess.run(["dot", ...])` covers the actual
"render to PNG if Graphviz is installed" requirement without a new
dependency this project did not otherwise need.
"""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
from pathlib import Path

import networkx as nx


def build_handoff_graph(conn: sqlite3.Connection) -> nx.DiGraph:
    """Build a NetworkX DiGraph of group nodes + real hands_off_to edges only."""
    graph = nx.DiGraph()
    for row in conn.execute("SELECT id, label FROM node WHERE type = 'group' ORDER BY id"):
        graph.add_node(row["id"], label=row["label"])
    for row in conn.execute(
        "SELECT src_id, dst_id, note FROM edge WHERE type = 'hands_off_to'"
    ):
        graph.add_edge(row["src_id"], row["dst_id"], note=row["note"] or "")
    return graph


def _dot_str(value: str) -> str:
    """Escape a string for embedding in a DOT double-quoted identifier/label.

    Backslash MUST be escaped before quote, not just quote alone: a label
    ending in a bare backslash (e.g. "Foo\\") would otherwise turn the
    closing quote into an escaped-quote (\\") in DOT's grammar, so the
    string never actually closes and DOT keeps consuming subsequent text
    -- corrupting the rest of the file. Found in security review; matches
    the fix already applied to export/storm.py's _storm_str.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(graph: nx.DiGraph) -> str:
    """Render a handoff DiGraph to plain Graphviz DOT text (hand-emitted, no pydot)."""
    lines = ["digraph handoff {", '  rankdir="LR";']
    for node_id, data in graph.nodes(data=True):
        label = data.get("label", node_id)
        lines.append(f'  "{_dot_str(node_id)}" [label="{_dot_str(label)}"];')
    for src, dst, data in graph.edges(data=True):
        note = data.get("note", "")
        if note:
            lines.append(
                f'  "{_dot_str(src)}" -> "{_dot_str(dst)}" [label="{_dot_str(note)}"];'
            )
        else:
            lines.append(f'  "{_dot_str(src)}" -> "{_dot_str(dst)}";')
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_handoff_graph(conn: sqlite3.Connection, out_dir: str | Path) -> dict:
    """Write the handoff model DOT file, and a PNG too if `dot` is on PATH.

    Args:
        conn: An open sqlite3.Connection.
        out_dir: Directory to write handoff.dot (and handoff.png if
            possible) into. Created if missing.

    Returns:
        {"dot_path": str, "png_path": str | None, "rendered": bool,
         "note": str | None} -- never raises just because Graphviz's
        `dot` binary is not installed; that case is reported, not failed.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    graph = build_handoff_graph(conn)
    dot_text = to_dot(graph)
    dot_path = out_dir / "handoff.dot"
    dot_path.write_text(dot_text, encoding="utf-8")

    result: dict = {"dot_path": str(dot_path), "png_path": None, "rendered": False, "note": None}

    dot_binary = shutil.which("dot")
    if dot_binary is None:
        result["note"] = (
            "Graphviz 'dot' binary not found on PATH; only handoff.dot was written. "
            "Install Graphviz (https://graphviz.org/download/) to render a PNG."
        )
        return result

    png_path = out_dir / "handoff.png"
    try:
        subprocess.run(
            [dot_binary, "-Tpng", str(dot_path), "-o", str(png_path)],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        result["note"] = f"Graphviz 'dot' was found but rendering failed: {exc}"
        return result

    result["png_path"] = str(png_path)
    result["rendered"] = True
    return result
