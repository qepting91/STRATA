"""Tests for strata.enrich.timeline against synthetic KEV/CSAF/NVD/signal data."""

from __future__ import annotations

import json
from datetime import date

from strata.enrich import timeline
from strata.model import store


def _insert_source(conn, sid: str) -> None:
    store.insert_source(conn, id=sid, name="test", url=None, fetched_at="2026-01-01T00:00:00Z")


def test_t_disclosed_prefers_earliest_of_three_sources(db_conn) -> None:
    """NVD published lags the vendor advisory by weeks -- t_disclosed must
    anchor on the earliest of the three, never NVD alone."""
    _insert_source(db_conn, "nvd-CVE-2024-0001")
    _insert_source(db_conn, "csaf-advisory-1")
    store.insert_node(
        db_conn,
        id="advisory-1",
        type="advisory",
        label="Advisory 1",
        attrs=json.dumps({"initial_release_date": "2024-01-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-0001",
        type="vuln",
        label="CVE-2024-0001",
        attrs=json.dumps({"nvd_published": "2024-02-15", "date_added": "2024-03-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_edge(
        db_conn, id="e-describes-1", src_id="advisory-1", dst_id="CVE-2024-0001",
        type="describes", source_id="csaf-advisory-1",
    )

    vuln = next(v for v in store.get_all_vuln_nodes(db_conn) if v["id"] == "CVE-2024-0001")
    tl = timeline.compute_cve_timeline(db_conn, vuln)

    assert tl.t_disclosed == date(2024, 1, 1)
    assert tl.t_disclosed_src == "csaf_advisory"
    assert tl.t_nvd_published == date(2024, 2, 15)
    assert tl.t_kev == date(2024, 3, 1)


def test_poc_corroboration_tier_high_via_cross_source(db_conn) -> None:
    _insert_source(db_conn, "src-poc")
    _insert_source(db_conn, "src-exploitdb")
    store.insert_signal(
        db_conn, id="sig-poc", cve="CVE-2024-0002", source="poc-github",
        signal_type="poc_repo_created", ref="https://github.com/x/y",
        observed_at="2024-01-10", meta=json.dumps({"stars": 2, "forks": 0}),
        source_id="src-poc",
    )
    store.insert_signal(
        db_conn, id="sig-edb", cve="CVE-2024-0002", source="exploitdb",
        signal_type="exploitdb_published", ref="https://example.test/1",
        observed_at="2024-01-15", meta=None, source_id="src-exploitdb",
    )
    store.insert_node(
        db_conn, id="CVE-2024-0002", type="vuln", label="CVE-2024-0002",
        attrs=None, created_at="2026-01-01T00:00:00Z",
    )
    vuln = {"id": "CVE-2024-0002", "label": "CVE-2024-0002", "attrs": None}
    tl = timeline.compute_cve_timeline(db_conn, vuln)
    assert tl.t_first_poc == date(2024, 1, 10)
    assert tl.t_first_poc_source_id == "src-poc"
    assert tl.t_first_poc_claimed == date(2024, 1, 10)


def test_poc_corroboration_tier_high_via_stars(db_conn) -> None:
    _insert_source(db_conn, "src-poc2")
    store.insert_signal(
        db_conn, id="sig-poc2", cve="CVE-2024-0003", source="poc-github",
        signal_type="poc_repo_created", ref="https://github.com/x/y",
        observed_at="2024-01-10", meta=json.dumps({"stars": 50, "forks": 3}),
        source_id="src-poc2",
    )
    vuln = {"id": "CVE-2024-0003", "label": "CVE-2024-0003", "attrs": None}
    tl = timeline.compute_cve_timeline(db_conn, vuln)
    assert tl.t_first_poc == date(2024, 1, 10)


def test_poc_with_low_stars_and_no_corroboration_is_moderate_not_excluded(db_conn) -> None:
    """moderate still counts toward t_first_poc (only 'low' would be
    excluded, and this project does not have enough signal to assign a
    genuine 'low' tier -- see module docstring)."""
    _insert_source(db_conn, "src-poc3")
    store.insert_signal(
        db_conn, id="sig-poc3", cve="CVE-2024-0004", source="poc-github",
        signal_type="poc_repo_created", ref="https://github.com/x/y",
        observed_at="2024-01-10", meta=json.dumps({"stars": 1, "forks": 0}),
        source_id="src-poc3",
    )
    vuln = {"id": "CVE-2024-0004", "label": "CVE-2024-0004", "attrs": None}
    tl = timeline.compute_cve_timeline(db_conn, vuln)
    assert tl.t_first_poc == date(2024, 1, 10)


def test_derived_interval_math_disclosure_to_poc_days(db_conn) -> None:
    _insert_source(db_conn, "nvd-CVE-2024-0005")
    _insert_source(db_conn, "src-poc5")
    store.insert_node(
        db_conn, id="CVE-2024-0005", type="vuln", label="CVE-2024-0005",
        attrs=json.dumps({"nvd_published": "2024-01-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_signal(
        db_conn, id="sig-poc5", cve="CVE-2024-0005", source="poc-github",
        signal_type="poc_repo_created", ref="https://github.com/x/y",
        observed_at="2024-01-11", meta=json.dumps({"stars": 20, "forks": 0}),
        source_id="src-poc5",
    )

    summary = timeline.run(db_conn)
    assert summary["metrics_written"] >= 1

    row = db_conn.execute(
        "SELECT value, source_id FROM metric_observation WHERE id = ?",
        ("CVE-2024-0005--disclosure_to_poc_days",),
    ).fetchone()
    assert row["value"] == 10.0
    assert row["source_id"] == "src-poc5"


def test_negative_interval_is_recorded_not_dropped(db_conn) -> None:
    """A PoC claimed to predate disclosure is a data-quality signal worth
    recording, not silently discarding."""
    _insert_source(db_conn, "nvd-CVE-2024-0006")
    _insert_source(db_conn, "src-poc6")
    store.insert_node(
        db_conn, id="CVE-2024-0006", type="vuln", label="CVE-2024-0006",
        attrs=json.dumps({"nvd_published": "2024-05-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_signal(
        db_conn, id="sig-poc6", cve="CVE-2024-0006", source="poc-github",
        signal_type="poc_repo_created", ref="https://github.com/x/y",
        observed_at="2024-01-01", meta=json.dumps({"stars": 20, "forks": 0}),
        source_id="src-poc6",
    )
    timeline.run(db_conn)
    row = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0006--disclosure_to_poc_days",),
    ).fetchone()
    assert row["value"] == -121.0


def test_stale_metric_is_cleared_when_its_input_disappears_on_rerun(db_conn) -> None:
    """Regression test: a previous run's disclosure_to_poc_days row must
    not survive a rerun where the poc-github signal it depended on is
    gone (e.g. a corpus correction removed a bad/duplicate scrape).
    insert_metric_observation is upsert-by-id, so without an explicit
    clear-before-recompute step in run(), the stale row would sit in
    metric_observation forever -- the same staleness bug already fixed
    for enrich.protocol.run()'s `involves` edges via
    delete_edges_by_type(), applied here via
    delete_metric_observations_by_names()."""
    _insert_source(db_conn, "nvd-CVE-2024-0010")
    _insert_source(db_conn, "src-poc10")
    store.insert_node(
        db_conn, id="CVE-2024-0010", type="vuln", label="CVE-2024-0010",
        attrs=json.dumps({"nvd_published": "2024-01-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_signal(
        db_conn, id="sig-poc10", cve="CVE-2024-0010", source="poc-github",
        signal_type="poc_repo_created", ref="https://github.com/x/y",
        observed_at="2024-01-11", meta=json.dumps({"stars": 20, "forks": 0}),
        source_id="src-poc10",
    )

    timeline.run(db_conn)
    row = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0010--disclosure_to_poc_days",),
    ).fetchone()
    assert row is not None and row["value"] == 10.0

    # Simulate a corpus correction: the poc-github signal is removed.
    db_conn.execute("DELETE FROM signal WHERE id = 'sig-poc10'")
    db_conn.commit()

    timeline.run(db_conn)
    row_after = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0010--disclosure_to_poc_days",),
    ).fetchone()
    assert row_after is None


def test_missing_data_means_no_metric_computed(db_conn) -> None:
    """A CVE with no PoC signal at all must not produce a
    disclosure_to_poc_days row (nothing to compute), but must not error."""
    _insert_source(db_conn, "nvd-CVE-2024-0007")
    store.insert_node(
        db_conn, id="CVE-2024-0007", type="vuln", label="CVE-2024-0007",
        attrs=json.dumps({"nvd_published": "2024-05-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    summary = timeline.run(db_conn)
    row = db_conn.execute(
        "SELECT * FROM metric_observation WHERE id = ?",
        ("CVE-2024-0007--disclosure_to_poc_days",),
    ).fetchone()
    assert row is None
    assert summary["cves_with_disclosure"] >= 1


def test_disclosure_to_group_use_computed_from_exploits_edge_note(db_conn) -> None:
    """An exploits edge with a first_seen note yields disclosure_to_group_use,
    cited to the exploits edge's own source_id."""
    _insert_source(db_conn, "nvd-CVE-2024-0011")
    _insert_source(db_conn, "s-group-claim")
    store.insert_node(
        db_conn, id="CVE-2024-0011", type="vuln", label="CVE-2024-0011",
        attrs=json.dumps({"nvd_published": "2024-01-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn, id="test-group", type="group", label="TEST-GROUP",
        attrs=None, created_at="2026-01-01T00:00:00Z",
    )
    store.insert_edge(
        db_conn, id="test-group--exploits--CVE-2024-0011",
        src_id="test-group", dst_id="CVE-2024-0011",
        type="exploits", source_id="s-group-claim", note="2024-01-21",
    )

    timeline.run(db_conn)

    row = db_conn.execute(
        "SELECT value, source_id FROM metric_observation WHERE id = ?",
        ("CVE-2024-0011--disclosure_to_group_use",),
    ).fetchone()
    assert row is not None
    assert row["value"] == 20.0
    assert row["source_id"] == "s-group-claim"


def test_disclosure_to_group_use_skipped_without_t_disclosed(db_conn) -> None:
    """A first_seen note on a CVE with no computable t_disclosed must not
    produce a metric row (nothing to compute against), and must not error."""
    _insert_source(db_conn, "s-group-claim-2")
    store.insert_node(
        db_conn, id="CVE-2024-0012", type="vuln", label="CVE-2024-0012",
        attrs=None, created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn, id="test-group-2", type="group", label="TEST-GROUP-2",
        attrs=None, created_at="2026-01-01T00:00:00Z",
    )
    store.insert_edge(
        db_conn, id="test-group-2--exploits--CVE-2024-0012",
        src_id="test-group-2", dst_id="CVE-2024-0012",
        type="exploits", source_id="s-group-claim-2", note="2024-01-21",
    )
    timeline.run(db_conn)
    row = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0012--disclosure_to_group_use",),
    ).fetchone()
    assert row is None


def test_disclosure_to_group_use_is_stale_cleared_on_rerun(db_conn) -> None:
    """Regression test mirroring the disclosure_to_poc_days staleness test:
    disclosure_to_group_use must be in the derived-metric clear list, so a
    row whose underlying exploits edge note is removed does not survive a
    rerun."""
    _insert_source(db_conn, "nvd-CVE-2024-0013")
    _insert_source(db_conn, "s-group-claim-3")
    store.insert_node(
        db_conn, id="CVE-2024-0013", type="vuln", label="CVE-2024-0013",
        attrs=json.dumps({"nvd_published": "2024-01-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn, id="test-group-3", type="group", label="TEST-GROUP-3",
        attrs=None, created_at="2026-01-01T00:00:00Z",
    )
    store.insert_edge(
        db_conn, id="test-group-3--exploits--CVE-2024-0013",
        src_id="test-group-3", dst_id="CVE-2024-0013",
        type="exploits", source_id="s-group-claim-3", note="2024-01-21",
    )
    timeline.run(db_conn)
    row = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0013--disclosure_to_group_use",),
    ).fetchone()
    assert row is not None and row["value"] == 20.0

    db_conn.execute(
        "UPDATE edge SET note = NULL WHERE id = "
        "'test-group-3--exploits--CVE-2024-0013'"
    )
    db_conn.commit()

    timeline.run(db_conn)
    row_after = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0013--disclosure_to_group_use",),
    ).fetchone()
    assert row_after is None


def test_patch_available_at_kev_true_and_false(db_conn) -> None:
    _insert_source(db_conn, "nvd-CVE-2024-0008")
    _insert_source(db_conn, "nvd-CVE-2024-0009")
    store.insert_node(
        db_conn, id="CVE-2024-0008", type="vuln", label="CVE-2024-0008",
        attrs=json.dumps({"nvd_published": "2024-01-01", "date_added": "2024-02-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    store.insert_node(
        db_conn, id="CVE-2024-0009", type="vuln", label="CVE-2024-0009",
        attrs=json.dumps({"nvd_published": "2024-03-01", "date_added": "2024-02-01"}),
        created_at="2026-01-01T00:00:00Z",
    )
    timeline.run(db_conn)

    row8 = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0008--patch_available_at_kev",),
    ).fetchone()
    row9 = db_conn.execute(
        "SELECT value FROM metric_observation WHERE id = ?",
        ("CVE-2024-0009--patch_available_at_kev",),
    ).fetchone()
    assert row8["value"] == 1.0
    assert row9["value"] == 0.0
