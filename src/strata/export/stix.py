"""STIX 2.1 bundle export (spec section 8.2).

Builds one STIX object per group/tool/technique/vuln node plus one
Relationship per real edge connecting them, using the `stix2` library so
every object is schema-valid by construction; a test additionally
validates the serialized bundle with `stix2-validator`.

Object-type mapping (documented, since the spec only names the object
classes, not a per-field mapping):
  group     -> stix2.IntrusionSet (name=label, aliases=attrs.aliases)
  tool      -> stix2.Malware (is_family=False) if attrs.class suggests a
               named malicious implant/backdoor/webshell/loader, else
               stix2.Tool for dual-use/OSS utilities (e.g. Mimikatz,
               PsExec, frp) -- attrs.class in {"credential_theft",
               "lateral_movement", "tunnel"} maps to Tool; everything
               else maps to Malware. This is a judgment call this module
               documents rather than hides: STIX draws that line the
               same way ATT&CK does (S-designated software vs. dual-use
               admin tooling), and our corpus's own `oss`/`class` attrs
               are the closest signal available to approximate it.
  technique -> stix2.AttackPattern (name=label, external_references to
               MITRE ATT&CK using the node id, e.g. T1190)
  vuln      -> stix2.Vulnerability (name=CVE id, external_references to
               the CVE source)

Relationship-type mapping (closest standard STIX relationship_type per
https://docs.oasis-open.org/cti/stix/v2.1/ common relationships table):
  hands_off_to -> "related-to" between two intrusion-sets (STIX has no
                  literal "hands off operations to" vocabulary entry;
                  "related-to" is the closest generic type, corroborated
                  by an `x_strata_note`-free plain description in the
                  Relationship's own `description` field so the specific
                  handoff meaning is not silently lost).
  uses         -> "uses" (intrusion-set uses malware/tool -- a direct,
                  standard STIX vocabulary match).
  exploits     -> "targets" (intrusion-set targets vulnerability -- the
                  standard STIX common-relationship entry; STIX reserves
                  literal "exploits" for malware/tool -> vulnerability,
                  which this corpus's exploits edges do not model since
                  ours are always group -> vuln, not tool -> vuln).
  implements   -> "uses" (intrusion-set uses attack-pattern -- standard).
"""

from __future__ import annotations

import json
import sqlite3

import stix2

_DUAL_USE_TOOL_CLASSES = {"credential_theft", "lateral_movement", "tunnel"}

_RELATIONSHIP_TYPE = {
    "hands_off_to": "related-to",
    "uses": "uses",
    "exploits": "targets",
    "implements": "uses",
}

_NODE_TYPES = ("group", "tool", "technique", "vuln")
_EDGE_TYPES = ("hands_off_to", "uses", "exploits", "implements")


def _make_intrusion_set(node_id: str, label: str, attrs: dict) -> stix2.IntrusionSet:
    aliases = attrs.get("aliases") or []
    kwargs: dict = {"name": label}
    if aliases:
        kwargs["aliases"] = [str(a) for a in aliases]
    return stix2.IntrusionSet(**kwargs)


def _make_tool_or_malware(label: str, attrs: dict) -> stix2.Malware | stix2.Tool:
    tool_class = attrs.get("class")
    if tool_class in _DUAL_USE_TOOL_CLASSES:
        return stix2.Tool(name=label)
    return stix2.Malware(name=label, is_family=False)


def _make_attack_pattern(node_id: str, label: str) -> stix2.AttackPattern:
    return stix2.AttackPattern(
        name=label,
        external_references=[
            {"source_name": "mitre-attack", "external_id": node_id}
        ],
    )


def _make_vulnerability(node_id: str) -> stix2.Vulnerability:
    return stix2.Vulnerability(
        name=node_id,
        external_references=[{"source_name": "cve", "external_id": node_id}],
    )


def build_stix_bundle(conn: sqlite3.Connection) -> stix2.Bundle:
    """Build a STIX 2.1 Bundle from the graph's group/tool/technique/vuln nodes
    and the real hands_off_to/uses/exploits/implements edges connecting them.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.

    Returns:
        A stix2.Bundle containing one SDO per qualifying node and one
        Relationship per qualifying edge.
    """
    objects: list = []
    stix_id_by_node: dict[str, str] = {}

    node_placeholders = ",".join("?" for _ in _NODE_TYPES)
    node_rows = conn.execute(
        f"SELECT id, type, label, attrs FROM node WHERE type IN ({node_placeholders}) "
        f"ORDER BY type, id",
        _NODE_TYPES,
    ).fetchall()

    for row in node_rows:
        attrs = {}
        if row["attrs"]:
            try:
                attrs = json.loads(row["attrs"])
            except json.JSONDecodeError:
                attrs = {}

        if row["type"] == "group":
            obj = _make_intrusion_set(row["id"], row["label"], attrs)
        elif row["type"] == "tool":
            obj = _make_tool_or_malware(row["label"], attrs)
        elif row["type"] == "technique":
            obj = _make_attack_pattern(row["id"], row["label"])
        else:
            obj = _make_vulnerability(row["id"])

        objects.append(obj)
        stix_id_by_node[row["id"]] = obj.id

    edge_placeholders = ",".join("?" for _ in _EDGE_TYPES)
    edge_rows = conn.execute(
        f"SELECT type, src_id, dst_id FROM edge WHERE type IN ({edge_placeholders}) "
        f"ORDER BY type, src_id, dst_id",
        _EDGE_TYPES,
    ).fetchall()

    for row in edge_rows:
        src_stix_id = stix_id_by_node.get(row["src_id"])
        dst_stix_id = stix_id_by_node.get(row["dst_id"])
        if src_stix_id is None or dst_stix_id is None:
            continue
        relationship_type = _RELATIONSHIP_TYPE[row["type"]]
        objects.append(
            stix2.Relationship(
                relationship_type=relationship_type,
                source_ref=src_stix_id,
                target_ref=dst_stix_id,
                description=f"strata edge type: {row['type']}",
            )
        )

    return stix2.Bundle(objects=objects)
