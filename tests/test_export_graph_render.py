"""Tests for strata.export.graph_render: DOT emission + dot-binary-present/absent paths."""

from __future__ import annotations

from pathlib import Path

from strata.export.graph_render import build_handoff_graph, render_handoff_graph, to_dot
from strata.model import store

_FETCHED = "2026-01-01T00:00:00Z"


def _seed(conn) -> None:
    store.insert_source(conn, id="s-1", name="test", url=None, fetched_at=_FETCHED)
    store.insert_node(
        conn, id="group-a", type="group", label="GROUP A", attrs=None, created_at=_FETCHED
    )
    store.insert_node(
        conn, id="group-b", type="group", label="GROUP B", attrs=None, created_at=_FETCHED
    )
    store.insert_edge(
        conn, id="e1", src_id="group-a", dst_id="group-b",
        type="hands_off_to", source_id="s-1", note="high confidence",
    )


def test_build_handoff_graph_only_includes_group_and_handsoff(db_conn) -> None:
    _seed(db_conn)
    store.insert_node(
        db_conn, id="tool-x", type="tool", label="ToolX", attrs=None, created_at=_FETCHED
    )
    store.insert_edge(
        db_conn, id="e2", src_id="group-a", dst_id="tool-x", type="uses", source_id="s-1"
    )
    graph = build_handoff_graph(db_conn)
    assert set(graph.nodes) == {"group-a", "group-b"}
    assert graph.has_edge("group-a", "group-b")


def test_to_dot_produces_digraph_text(db_conn) -> None:
    _seed(db_conn)
    graph = build_handoff_graph(db_conn)
    dot_text = to_dot(graph)
    assert dot_text.startswith("digraph handoff {")
    assert '"group-a" -> "group-b"' in dot_text
    assert "high confidence" in dot_text


def test_to_dot_escapes_trailing_backslash_before_quote(db_conn) -> None:
    """Regression test (security review finding): escaping only `"` (not
    `\\` first) means a label ending in a backslash, e.g. 'Foo\\', would
    render as "Foo\\" -- DOT's grammar reads \\" as an escaped quote, not
    a string terminator, so the string never closes and DOT keeps
    consuming the rest of the file. Backslash must be escaped before
    quote, matching export/storm.py's _storm_str."""
    store.insert_source(db_conn, id="s-1", name="test", url=None, fetched_at=_FETCHED)
    store.insert_node(
        db_conn, id="group-a", type="group", label='Trailing\\', attrs=None,
        created_at=_FETCHED,
    )
    store.insert_node(
        db_conn, id="group-b", type="group", label="GROUP B", attrs=None,
        created_at=_FETCHED,
    )
    store.insert_edge(
        db_conn, id="e1", src_id="group-a", dst_id="group-b",
        type="hands_off_to", source_id="s-1", note=None,
    )
    graph = build_handoff_graph(db_conn)
    dot_text = to_dot(graph)
    # The backslash must be doubled, and the quote that follows it must
    # still be the label's own closing quote, not consumed as an escape.
    assert '[label="Trailing\\\\"];' in dot_text
    # And the file must still be well-formed after that node: group-b's
    # own node line must appear intact, not swallowed into group-a's label.
    assert '"group-b" [label="GROUP B"];' in dot_text


def test_render_handoff_graph_without_dot_binary(db_conn, tmp_path: Path, monkeypatch) -> None:
    _seed(db_conn)
    monkeypatch.setattr("strata.export.graph_render.shutil.which", lambda name: None)
    result = render_handoff_graph(db_conn, tmp_path)
    assert result["rendered"] is False
    assert result["png_path"] is None
    assert Path(result["dot_path"]).exists()
    assert result["note"] is not None


def test_render_handoff_graph_with_dot_binary(db_conn, tmp_path: Path, monkeypatch) -> None:
    _seed(db_conn)
    monkeypatch.setattr("strata.export.graph_render.shutil.which", lambda name: "/usr/bin/dot")

    def _fake_run(cmd, check, capture_output):
        # Simulate `dot` writing an (empty) PNG file at the -o path.
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_bytes(b"\x89PNG\r\n")

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr("strata.export.graph_render.subprocess.run", _fake_run)
    result = render_handoff_graph(db_conn, tmp_path)
    assert result["rendered"] is True
    assert result["png_path"] is not None
    assert Path(result["png_path"]).exists()
