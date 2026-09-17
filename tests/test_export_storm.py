"""Tests for strata.export.storm against a small fixture graph."""

from __future__ import annotations

from strata.export.storm import _form_ref, generate_storm, validate_storm_grammar
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
    store.insert_node(
        conn, id="CVE-2020-0001", type="vuln", label="CVE-2020-0001",
        attrs=None, created_at=_FETCHED,
    )
    store.insert_node(
        conn, id="tool-x", type="tool", label="ToolX", attrs=None, created_at=_FETCHED
    )
    store.insert_edge(
        conn, id="e1", src_id="group-a", dst_id="group-b",
        type="hands_off_to", source_id="s-1", note="high confidence",
    )
    store.insert_edge(
        conn, id="e2", src_id="group-a", dst_id="CVE-2020-0001",
        type="exploits", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e3", src_id="group-b", dst_id="tool-x",
        type="uses", source_id="s-1",
    )


def test_generate_storm_produces_valid_grammar(db_conn) -> None:
    _seed(db_conn)
    text = generate_storm(db_conn)
    assert validate_storm_grammar(text)
    assert 'risk:threat=(strata, "group-a")' in text
    assert 'risk:vuln=(cve, "CVE-2020-0001")' in text
    assert 'it:prod:soft=(strata, "tool-x")' in text
    assert "-(hands-off-to)>" in text
    assert "-(exploits)>" in text
    assert "-(uses)>" in text


def test_generate_storm_includes_evidence_comment(db_conn) -> None:
    _seed(db_conn)
    text = generate_storm(db_conn)
    assert "// evidence: high confidence" in text


def test_validate_storm_grammar_rejects_unbalanced_brackets() -> None:
    assert not validate_storm_grammar("[ risk:threat=(strata, x)\n    :name=\"x\"\n")


def test_form_ref_quotes_and_escapes_tool_and_technique_ids() -> None:
    """Regression test (security review finding): only the vuln branch of
    _form_ref used to quote/escape its node_id; tool/technique/group ids
    were spliced raw into the Storm tuple, since Tool.name/attack_id/group
    id carry no regex constraint in normalize/models.py. A tool name
    containing a paren/comma/quote could break out of the tuple and
    corrupt the generated .storm file's structure. All four branches must
    now quote+escape consistently."""
    assert _form_ref("tool-o_reilly", "tool") == 'it:prod:soft=(strata, "tool-o_reilly")'
    assert _form_ref('tool-inject"), risk:threat=(strata, "pwned', "tool") == (
        'it:prod:soft=(strata, "tool-inject\\"), risk:threat=(strata, \\"pwned")'
    )
    assert _form_ref("T1190", "technique") == 'ou:technique=(strata, "T1190")'
    assert _form_ref("sylvanite", "group") == 'risk:threat=(strata, "sylvanite")'


def test_validate_storm_grammar_rejects_empty_text() -> None:
    assert not validate_storm_grammar("")
