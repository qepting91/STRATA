"""Tests for strata.export.stix: bundle building + validation.

stix2-validator's schema-based validate_string() is attempted, but this
environment's pip-installed `stix2-validator` package (3.3.1) ships with
zero JSON schema files at all (verified: importlib.metadata.files finds
none under schemas-2.1/), so validate_string() always raises a
SchemaError -- even for a trivially valid single-object bundle -- because
upstream expects a separately-vendored copy of the OASIS
cti-stix2-json-schemas repository, which this project cannot fetch under
its own egress-guard policy. This is a real, documented environment
limitation, not a bug in our bundle. So this test asserts the *specific*
known-missing-schema failure mode (proving the gap is packaging, not
content) and, as the actually-meaningful validation for this pass, relies
on the `stix2` library's own strict object-construction/parse validation
(round-tripping the serialized bundle through stix2.parse() -- which
raises on any structurally invalid STIX 2.1 object).
"""

from __future__ import annotations

import stix2

from strata.export.stix import build_stix_bundle
from strata.model import store

_FETCHED = "2026-01-01T00:00:00Z"


def _seed(conn) -> None:
    import json

    store.insert_source(conn, id="s-1", name="test", url=None, fetched_at=_FETCHED)
    store.insert_node(
        conn, id="group-a", type="group", label="GROUP A",
        attrs=json.dumps({"aliases": ["ALIAS A"]}), created_at=_FETCHED,
    )
    store.insert_node(
        conn, id="group-b", type="group", label="GROUP B", attrs=None, created_at=_FETCHED
    )
    store.insert_node(
        conn, id="tool-malware", type="tool", label="EvilImplant",
        attrs=json.dumps({"class": "backdoor"}), created_at=_FETCHED,
    )
    store.insert_node(
        conn, id="tool-dualuse", type="tool", label="Mimikatz",
        attrs=json.dumps({"class": "credential_theft"}), created_at=_FETCHED,
    )
    store.insert_node(
        conn, id="T1190", type="technique", label="Exploit Public-Facing Application",
        attrs=None, created_at=_FETCHED,
    )
    store.insert_node(
        conn, id="CVE-2020-0001", type="vuln", label="CVE-2020-0001",
        attrs=None, created_at=_FETCHED,
    )
    store.insert_edge(
        conn, id="e1", src_id="group-a", dst_id="group-b",
        type="hands_off_to", source_id="s-1",
    )
    store.insert_edge(
        conn, id="e2", src_id="group-a", dst_id="tool-malware", type="uses", source_id="s-1"
    )
    store.insert_edge(
        conn, id="e3", src_id="group-a", dst_id="tool-dualuse", type="uses", source_id="s-1"
    )
    store.insert_edge(
        conn, id="e4", src_id="group-a", dst_id="T1190", type="implements", source_id="s-1"
    )
    store.insert_edge(
        conn, id="e5", src_id="group-a", dst_id="CVE-2020-0001",
        type="exploits", source_id="s-1",
    )


def test_build_stix_bundle_object_counts(db_conn) -> None:
    _seed(db_conn)
    bundle = build_stix_bundle(db_conn)
    types = [obj["type"] for obj in bundle.objects]
    assert types.count("intrusion-set") == 2
    assert types.count("malware") == 1
    assert types.count("tool") == 1
    assert types.count("attack-pattern") == 1
    assert types.count("vulnerability") == 1
    assert types.count("relationship") == 5


def test_stix_bundle_round_trips_through_stix2_parse(db_conn) -> None:
    """The practical validation: stix2's own strict parser accepts the
    serialized bundle without error, and every relationship_type is a
    recognized STIX 2.1 string."""
    _seed(db_conn)
    bundle = build_stix_bundle(db_conn)
    serialized = bundle.serialize()
    reparsed = stix2.parse(serialized, allow_custom=False)
    assert reparsed.type == "bundle"
    relationship_types = {
        obj["relationship_type"] for obj in reparsed.objects if obj["type"] == "relationship"
    }
    assert relationship_types == {"related-to", "uses", "targets"}


def test_stix2_validator_fails_on_missing_schemas_not_our_content() -> None:
    """Documents the real environment gap: even a trivially valid bundle
    fails stix2-validator's schema-based check here, because this pip
    package ships with no JSON schema files at all."""
    from stix2validator import validate_string

    trivial = stix2.Bundle(
        objects=[stix2.Identity(name="trivial", identity_class="organization")]
    )
    results = validate_string(trivial.serialize())
    assert results.is_valid is False
    assert any(type(e).__name__ == "SchemaError" for e in results.errors)
