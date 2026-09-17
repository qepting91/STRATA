"""Tests for strata.enrich.protocol -- synthetic-text unit tests.

Real-world near-misses (a keyword appearing in an unrelated product blurb
while the actual vuln is elsewhere) are what the future 200-CVE validation
set actually measures; these synthetic cases just prove the classify()
mechanics work as designed.
"""

from __future__ import annotations

import json

from strata.enrich import protocol
from strata.model import store

RULES = protocol.load_protocol_rules()


def test_clear_single_protocol_match() -> None:
    text = "A vulnerability in the Modbus TCP server allows unauthenticated write access."
    results = protocol.classify(text, RULES)
    assert len(results) == 1
    assert results[0].protocol_name == "Modbus"
    assert results[0].evidence == "keyword:modbus"


def test_multi_protocol_match() -> None:
    text = (
        "The device exposes both a Modbus interface and an OPC UA endpoint; "
        "an attacker can pivot between them."
    )
    results = protocol.classify(text, RULES)
    names = {r.protocol_name for r in results}
    assert names == {"Modbus", "OPC-UA"}


def test_function_code_corroboration() -> None:
    text = (
        "An issue in the Modbus implementation allows sending function code 6 "
        "to write a single register without authentication."
    )
    results = protocol.classify(text, RULES)
    assert len(results) == 1
    assert results[0].protocol_name == "Modbus"
    assert "keyword:modbus" in results[0].evidence
    assert "+function_code:6" in results[0].evidence


def test_keyword_in_unrelated_context_is_still_a_keyword_match() -> None:
    """Hand-constructed near-miss: MQTT mentioned among many supported
    protocols in a product blurb while the real flaw is an unrelated HTTP
    admin interface. classify() has no semantic understanding of "the
    actual vuln" -- it is a keyword matcher, so this legitimately still
    matches (a precision cost documented as a known limitation; the real
    200-CVE validation set is what will measure how often this happens in
    practice, not this synthetic test)."""
    text = (
        "The XYZ gateway supports Modbus, DNP3, MQTT, and BACnet for field "
        "device communication. A cross-site scripting flaw exists in the "
        "device's HTTP administrative web interface."
    )
    results = protocol.classify(text, RULES)
    names = {r.protocol_name for r in results}
    assert names == {"Modbus", "DNP3", "MQTT", "BACnet"}


def test_no_match() -> None:
    text = "A SQL injection vulnerability in the login form allows authentication bypass."
    results = protocol.classify(text, RULES)
    assert results == []


def test_keyword_as_substring_of_unrelated_word_is_not_a_match() -> None:
    """Regression test: two real false positives found live while building
    the Week 3 validation set, before word-boundary matching was added.
    "Mongoose Web Server" contains "goose" (IEC-61850's GOOSE keyword);
    "heapdump" contains "apdu" (IEC-104's APDU keyword). Neither CVE has
    anything to do with either protocol."""
    mongoose_text = (
        "Improper Neutralization of Delimiters vulnerability in Cesanta "
        "Mongoose Web Server v7.14 allows an out-of-bound memory write."
    )
    heapdump_text = (
        "The TeleMessage service configures Spring Boot Actuator with an "
        "exposed heap dump endpoint at a /heapdump URI, as exploited in "
        "the wild."
    )
    assert protocol.classify(mongoose_text, RULES) == []
    assert protocol.classify(heapdump_text, RULES) == []


def test_bare_port_number_without_keyword_is_not_a_match() -> None:
    text = "The service listens on port 502 for management traffic."
    results = protocol.classify(text, RULES)
    assert results == []


def test_port_corroboration_only_alongside_keyword() -> None:
    text = "A Modbus server on port 502 accepts unauthenticated write requests."
    results = protocol.classify(text, RULES)
    assert len(results) == 1
    assert "keyword:modbus" in results[0].evidence
    assert "+port:502" in results[0].evidence


def test_run_writes_involves_edges_with_evidence_note(db_conn) -> None:
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_source(
        db_conn, id="nvd-CVE-2024-5555", name="nvd", url=None, fetched_at=fetched_at,
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-5555",
        type="vuln",
        label="CVE-2024-5555",
        attrs=json.dumps(
            {"description": "A flaw in the Modbus function code 3 handler."}
        ),
        created_at=fetched_at,
    )

    summary = protocol.run(db_conn)

    assert summary["vulns_with_description"] == 1
    assert summary["edges_written"] == 1
    assert summary["protocols_matched"] == 1
    assert summary["vulns_skipped_missing_source"] == 0

    row = db_conn.execute(
        "SELECT note, type FROM edge WHERE src_id = ? AND dst_id = ?",
        ("CVE-2024-5555", "protocol-modbus"),
    ).fetchone()
    assert row["type"] == "involves"
    assert "keyword:modbus" in row["note"]


def test_run_matches_csaf_product_text_with_correct_advisory_source_id(db_conn) -> None:
    """A CVE with no NVD description match but a CSAF product-tree text
    match must still produce a correctly-sourced involves edge citing the
    CSAF advisory's own source_id, not a nonexistent nvd-<cve> one."""
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_source(
        db_conn, id="cisa-csaf-ICSA-26-100-01", name="cisa-csaf", url=None,
        fetched_at=fetched_at,
    )
    store.insert_node(
        db_conn, id="ICSA-26-100-01", type="advisory", label="Test Advisory",
        attrs=json.dumps({"initial_release_date": "2026-01-01"}),
        created_at=fetched_at,
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-7777",
        type="vuln",
        label="CVE-2024-7777",
        attrs=json.dumps(
            {"csaf_product_text": "Acme Modbus TCP Gateway v3 firmware"}
        ),
        created_at=fetched_at,
    )
    store.insert_edge(
        db_conn, id="ICSA-26-100-01--describes--CVE-2024-7777",
        src_id="ICSA-26-100-01", dst_id="CVE-2024-7777",
        type="describes", source_id="cisa-csaf-ICSA-26-100-01",
    )

    summary = protocol.run(db_conn)

    assert summary["vulns_with_description"] == 0
    assert summary["vulns_with_csaf_product_text"] == 1
    assert summary["edges_written"] == 1
    assert summary["vulns_skipped_missing_source"] == 0

    row = db_conn.execute(
        "SELECT note, type, source_id FROM edge WHERE src_id = ? AND dst_id = ?",
        ("CVE-2024-7777", "protocol-modbus"),
    ).fetchone()
    assert row["type"] == "involves"
    assert row["source_id"] == "cisa-csaf-ICSA-26-100-01"
    assert "keyword:modbus" in row["note"]
    assert "+source:csaf" in row["note"]

    # No dangling nvd-<cve> source row was ever created or cited.
    assert not store.source_exists(db_conn, "nvd-CVE-2024-7777")


def test_run_writes_both_nvd_and_csaf_edges_when_both_match(db_conn) -> None:
    """A CVE with matches from both text sources gets two independent
    involves edges, each with its own correct source_id -- not deduped."""
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_source(
        db_conn, id="nvd-CVE-2024-8888", name="nvd", url=None, fetched_at=fetched_at,
    )
    store.insert_source(
        db_conn, id="cisa-csaf-ICSA-26-200-01", name="cisa-csaf", url=None,
        fetched_at=fetched_at,
    )
    store.insert_node(
        db_conn, id="ICSA-26-200-01", type="advisory", label="Test Advisory 2",
        attrs=json.dumps({"initial_release_date": "2026-01-01"}),
        created_at=fetched_at,
    )
    store.insert_node(
        db_conn,
        id="CVE-2024-8888",
        type="vuln",
        label="CVE-2024-8888",
        attrs=json.dumps(
            {
                "description": "A flaw in the Modbus function code handler.",
                "csaf_product_text": "Acme Modbus TCP Gateway v3 firmware",
            }
        ),
        created_at=fetched_at,
    )
    store.insert_edge(
        db_conn, id="ICSA-26-200-01--describes--CVE-2024-8888",
        src_id="ICSA-26-200-01", dst_id="CVE-2024-8888",
        type="describes", source_id="cisa-csaf-ICSA-26-200-01",
    )

    summary = protocol.run(db_conn)
    assert summary["edges_written"] == 2

    rows = db_conn.execute(
        "SELECT note, source_id FROM edge WHERE src_id = ? AND dst_id = ? "
        "ORDER BY source_id",
        ("CVE-2024-8888", "protocol-modbus"),
    ).fetchall()
    assert len(rows) == 2
    source_ids = {row["source_id"] for row in rows}
    assert source_ids == {"nvd-CVE-2024-8888", "cisa-csaf-ICSA-26-200-01"}


def test_run_skips_when_no_matching_source_row(db_conn) -> None:
    """A vuln with a description but no nvd-<cve> source row is a real
    data inconsistency -- classifier must skip it (not crash, not insert
    an edge with a dangling source_id)."""
    fetched_at = "2026-01-01T00:00:00Z"
    store.insert_node(
        db_conn,
        id="CVE-2024-6666",
        type="vuln",
        label="CVE-2024-6666",
        attrs=json.dumps({"description": "A DNP3 outstation buffer overflow."}),
        created_at=fetched_at,
    )
    summary = protocol.run(db_conn)
    assert summary["vulns_skipped_missing_source"] == 1
    assert summary["edges_written"] == 0
