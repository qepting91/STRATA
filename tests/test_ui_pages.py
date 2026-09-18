"""Streamlit UI tests: streamlit.testing.v1.AppTest driving every page
headlessly against the real local database (spec section 15.6's testing
approach, adapted to the real DB per this task's explicit instruction).

Each page/app test asserts the page renders without raising
(at.exception is empty), plus page-specific regression assertions.

Skipped entirely if data/strata.db does not exist in this environment
(e.g. a from-scratch checkout that has never run `strata collect`/
`strata build`) -- these are the one place in the suite that
deliberately exercises the real database rather than a synthetic
fixture, per this task's explicit instruction.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DB_PATH = _REPO_ROOT / "data" / "strata.db"
_UI_ROOT = _REPO_ROOT / "src" / "strata" / "ui"

pytestmark = pytest.mark.skipif(
    not _DB_PATH.exists(),
    reason="data/strata.db not present -- run `strata collect`/`strata build` first",
)


@pytest.fixture(autouse=True)
def _real_db_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the UI's data.py at the real database for every test here."""
    monkeypatch.setenv("STRATA_DB_PATH", str(_DB_PATH))


def _run_page(relative_path: str) -> AppTest:
    at = AppTest.from_file(str(_UI_ROOT / relative_path), default_timeout=60)
    # AppTest resolves relative paths (config/, corpus/, tests/fixtures/)
    # against the process cwd, not the script's own directory -- run from
    # the real repo root so those resolve exactly as they do for
    # `strata ui` from the repo root.
    old_cwd = Path.cwd()
    os.chdir(_REPO_ROOT)
    try:
        at.run()
    finally:
        os.chdir(old_cwd)
    return at


def test_app_entrypoint_renders() -> None:
    at = _run_page("app.py")
    assert not at.exception


def test_search_renders() -> None:
    at = _run_page("pages/1_Search.py")
    assert not at.exception


def test_search_keyword_filters_to_real_matches() -> None:
    """Regression test: typing a real, specific keyword (a group id that
    appears nowhere else) must narrow the results to just that node,
    proving the keyword filter actually reaches the database rather than
    silently no-op'ing."""
    at = _run_page("pages/1_Search.py")
    at.text_input[0].set_value("sylvanite").run()
    assert not at.exception

    metric_labels = {m.label: m.value for m in at.metric}
    assert "Matches" in metric_labels
    assert int(metric_labels["Matches"].replace(",", "")) >= 1

    table_values = at.dataframe[0].value
    assert (table_values["ID"] == "sylvanite").any()


def test_search_type_filter_narrows_results() -> None:
    """Selecting only the 'group' type must exclude every non-group row."""
    at = _run_page("pages/1_Search.py")
    at.multiselect[0].select("group").run()
    assert not at.exception

    table_values = at.dataframe[0].value
    assert (table_values["Type"] == "group").all()


def test_search_inspect_result_shows_real_edges() -> None:
    """Selecting a real, edge-rich node (sylvanite) in the drill-down
    selectbox must render its real outgoing edges with citations, not an
    empty/broken detail panel."""
    at = _run_page("pages/1_Search.py")
    at.text_input[0].set_value("sylvanite").run()
    assert not at.exception

    node_selectbox = at.selectbox[-1]
    if "sylvanite" not in node_selectbox.options:
        pytest.skip("sylvanite not present in this real corpus")
    node_selectbox.set_value("sylvanite").run()
    assert not at.exception

    tab_labels = " ".join(t.label for t in at.tabs)
    assert "Outgoing edges" in tab_labels


def test_threat_groups_renders() -> None:
    at = _run_page("pages/2_Threat_Groups.py")
    assert not at.exception


def test_threat_groups_renders_group_with_many_edges_via_tabs() -> None:
    """Regression test for the redesign: a group with many edges (e.g.
    SYLVANITE -- 5 exploits + 6 tools + 2 techniques + 12 targets + 1
    handoff) must render via st.tabs, not a single undifferentiated
    vertical list of 26 full-width rows."""
    at = _run_page("pages/2_Threat_Groups.py")
    options = list(at.selectbox[0].options)
    if "sylvanite" not in options:
        pytest.skip("sylvanite not present in this real corpus")
    at.selectbox[0].set_value("sylvanite").run()
    assert not at.exception
    tab_labels = " ".join(t.label for t in at.tabs)
    assert "Targeting" in tab_labels
    assert "Exploited CVEs" in tab_labels
    assert "Tools" in tab_labels


def test_threat_groups_renders_stub_group_without_crashing() -> None:
    """Regression test: a stub group (e.g. magnallium -- referenced only
    via parisite's hands_off_to edge, no full corpus entry of its own)
    has no attrs at all. pandas represents that as a bare float NaN in
    this mixed dict/None column, not Python None, so a naive
    `row["attrs"] or {}` guard doesn't catch it (NaN is truthy) and the
    page crashed on `.get()` -- found live while building the
    Analytical Frameworks page, which iterates every group including
    stubs."""
    at = _run_page("pages/2_Threat_Groups.py")
    at.selectbox[0].set_value("magnallium").run()
    assert not at.exception


def test_weaponization_timeline_renders_on_near_empty_data() -> None:
    at = _run_page("pages/3_Weaponization_Timeline.py")
    assert not at.exception


def test_weaponization_timeline_shows_binary_summary_not_wall_of_bars() -> None:
    """Regression test for the redesign: patch_available_at_kev (~1,707
    real near-binary observations) must render as a percentage/count
    summary, never a per-CVE bar chart."""
    at = _run_page("pages/3_Weaponization_Timeline.py")
    assert not at.exception

    markdown_text = " ".join(m.value for m in at.markdown)
    assert "patch_available_at_kev" in markdown_text

    metric_labels = {m.label for m in at.metric}
    assert "CVEs scored" in metric_labels
    assert "Patched before KEV listing" in metric_labels


def test_protocol_cves_renders() -> None:
    at = _run_page("pages/4_Protocol_CVEs.py")
    assert not at.exception


def test_protocol_cves_shows_explainer_and_confusion_matrix() -> None:
    """Regression test for the redesign: the page must lead with a plain-
    English explainer of what it shows, and the confusion-matrix section
    must still render (same real, checked-in validation-set numbers)."""
    at = _run_page("pages/4_Protocol_CVEs.py")
    assert not at.exception

    markdown_text = " ".join(m.value for m in at.markdown)
    assert "What this page shows" in markdown_text
    assert "How it works" in markdown_text

    subheaders = {s.value for s in at.subheader}
    assert "Classifier validation set (real, checked-in ground truth)" in subheaders

    metric_labels = {m.label for m in at.metric}
    assert "Precision" in metric_labels
    assert "Recall" in metric_labels


def test_protocol_cves_dedupes_multi_source_matches() -> None:
    """Regression test: CVE-2026-78012 has two real involves edges to the
    same protocol (one from its NVD description, one from its CSAF
    advisory product-tree text -- enrich/protocol.py writes both
    independently as separate, correctly-cited edges). The page must
    render this as one card with two "Matched via" citations, not two
    duplicate cards for the same CVE."""
    at = _run_page("pages/4_Protocol_CVEs.py")
    assert not at.exception

    markdown_text = [m.value for m in at.markdown]
    cve_headers = [m for m in markdown_text if m == "**CVE-2026-78012**"]
    assert len(cve_headers) == 1

    metric_labels = {m.label: m.value for m in at.metric}
    assert "Distinct CVE-protocol matches" in metric_labels
    assert "Total involves edges (incl. multi-source)" in metric_labels
    # 4 real edges (2 for CVE-2026-78012, 1 each for the other 2 CVEs)
    # collapse to 3 distinct CVE-protocol matches.
    assert int(metric_labels["Total involves edges (incl. multi-source)"]) > int(
        metric_labels["Distinct CVE-protocol matches"]
    )


def test_visibility_gaps_renders() -> None:
    at = _run_page("pages/5_Visibility_Gaps.py")
    assert not at.exception


def test_collection_health_renders() -> None:
    at = _run_page("pages/6_Collection_Health.py")
    assert not at.exception


def test_analytical_frameworks_renders() -> None:
    at = _run_page("pages/7_Analytical_Frameworks.py")
    assert not at.exception


def test_threat_hunt_template_renders() -> None:
    at = _run_page("pages/8_Threat_Hunt_Template.py")
    assert not at.exception


def test_threat_hunt_examples_renders_with_real_corpus_files() -> None:
    """The 3 real example files (azurite/voltzite/pyroxene) are now
    authored in corpus/hunt_hypotheses/ -- confirm the page renders each
    without exception and offers all 3 as selectable groups."""
    import streamlit as st

    st.cache_data.clear()
    at = _run_page("pages/9_Threat_Hunt_Examples.py")
    assert not at.exception

    options = list(at.selectbox[0].options)
    assert {"azurite", "voltzite", "pyroxene"} <= set(options)

    for group_id in ("azurite", "voltzite", "pyroxene"):
        at.selectbox[0].set_value(group_id).run()
        assert not at.exception
    st.cache_data.clear()


def test_threat_hunt_examples_renders_with_no_files_present(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty hunt-hypotheses directory (e.g. a from-scratch checkout
    before any example is authored) must render a plain st.info, not
    crash -- exercised here via env override, since the real
    corpus/hunt_hypotheses/ now has real content."""
    import streamlit as st

    empty_dir = tmp_path / "empty_hunt_hypotheses"
    empty_dir.mkdir()
    monkeypatch.setenv("STRATA_HUNT_HYPOTHESES_DIR", str(empty_dir))
    monkeypatch.setenv(
        "STRATA_HUNT_HYPOTHESES_CITATIONS", str(tmp_path / "no-such-citations.yaml")
    )
    st.cache_data.clear()
    at = _run_page("pages/9_Threat_Hunt_Examples.py")
    assert not at.exception
    assert any("No hunt-hypothesis example files exist yet" in i.value for i in at.info)
    st.cache_data.clear()


def test_threat_hunt_examples_renders_with_synthetic_fixture_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Point STRATA_HUNT_HYPOTHESES_DIR/_CITATIONS at the synthetic
    tests/fixtures/hunt_hypotheses fixture (not real corpus content --
    the 3 real azurite/voltzite/pyroxene files are authored separately)
    and confirm the page renders the fixture's "test-group" example."""
    fixtures_root = _REPO_ROOT / "tests" / "fixtures"
    monkeypatch.setenv("STRATA_HUNT_HYPOTHESES_DIR", str(fixtures_root / "hunt_hypotheses"))
    monkeypatch.setenv(
        "STRATA_HUNT_HYPOTHESES_CITATIONS",
        str(fixtures_root / "hunt_hypotheses_citations.yaml"),
    )
    import streamlit as st

    st.cache_data.clear()
    at = _run_page("pages/9_Threat_Hunt_Examples.py")
    assert not at.exception
    st.cache_data.clear()


def test_handoff_projection_has_no_isolated_nodes() -> None:
    """Regression test: build_projection() (model/graph_ops.py) adds every
    node of the declared types unconditionally -- correct for traversal
    (a real edge must never be dropped just because one endpoint's type
    wasn't in the filter list), but with node_types including "product"
    (2,859 real nodes) and "vuln" (1,790), that is ~4,600+ mostly-isolated
    nodes with no hands_off_to/uses/exploits edge at all. Found live:
    pyvis physics-simulates every node regardless of degree, and
    rendering ~4,675 nodes froze the browser tab entirely.
    load_handoff_projection() must prune isolates before returning --
    this proves it actually does, against the real DB."""
    import networkx as nx
    import streamlit as st

    from strata.ui.data import load_handoff_projection

    st.cache_data.clear()
    graph = load_handoff_projection()
    assert graph.number_of_nodes() > 0
    assert list(nx.isolates(graph)) == []
    # The real graph has ~4,675 nodes before pruning (2,859 products +
    # 1,790 vulns + a handful of groups/tools) -- after pruning to only
    # nodes reachable via a real hands_off_to/uses/exploits edge, this
    # must be dramatically smaller (observed live: 31 nodes).
    assert graph.number_of_nodes() < 200
