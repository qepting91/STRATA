"""ICS protocol classifier (STRATA Week 3, spec section 6.2).

Rule-based, transparent, testable: classify() is a pure function over a
CVE description string and a list of ProtocolRule objects loaded from
config/protocols.yaml. run() wires that over every vuln node description
and writes vuln -[:involves]-> protocol edges.

Applied over both of spec section 6.2's stated inputs: CVE descriptions
(NVD attrs.description, cited to nvd-<cve>) and CSAF advisory product-tree
text (attrs.csaf_product_text, added to collect/cisa_csaf.py post-Week-4,
cited to that advisory's own source row -- resolved via the describes
edge, not NVD's). A CVE can match via either, both, or neither text
source; matches from each are written as independent involves edges with
their own correct source_id, never deduped across sources, since each is
an independently-cited claim (a CVE with both a description match and a
CSAF-text match for the same protocol legitimately gets two edges).

Evidence composition rule: primary evidence is a keyword match
(keyword:<kw>). Two corroborating (never sufficient alone) signals may be
appended: a function-code-shaped regex match ("function code N") where N
is a key in the matched protocol function_codes table
(+function_code:N), and the protocol port number appearing as a
standalone number in the text (+port:N) -- but only ever alongside an
existing keyword match, never on its own. A bare port-number mention with
no keyword match is not a match at all: ports are reused across unrelated
contexts far too often to be primary evidence.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

from strata.model import store

logger = logging.getLogger(__name__)

_FUNCTION_CODE_RE = re.compile(r"function code\s*(\d+)", re.IGNORECASE)


@dataclass
class ProtocolRule:
    """One row of config/protocols.yaml."""

    name: str
    ports: list[int] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    function_codes: dict[int, str] = field(default_factory=dict)


@dataclass
class ClassificationResult:
    """One protocol match for a piece of classified text."""

    protocol_name: str
    evidence: str


def load_protocol_rules(path: Path | str = "config/protocols.yaml") -> list[ProtocolRule]:
    """Load config/protocols.yaml into a list of ProtocolRule.

    Args:
        path: Path to the protocols YAML file.

    Returns:
        List of ProtocolRule, in file order.
    """
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    rules: list[ProtocolRule] = []
    for row in data:
        rules.append(
            ProtocolRule(
                name=row["name"],
                ports=list(row.get("ports") or []),
                keywords=[str(k) for k in (row.get("keywords") or [])],
                function_codes={int(k): v for k, v in (row.get("function_codes") or {}).items()},
            )
        )
    return rules


def _port_appears(text: str, port: int) -> bool:
    """Standalone-number check for a port mention (weak, corroborating only)."""
    return re.search(rf"\b{port}\b", text) is not None


def _keyword_matches(keyword: str, lower_text: str) -> bool:
    """Word-boundary-aware keyword search.

    A plain substring check (`keyword in text`) produces real false
    positives for short protocol-name fragments that are common English
    word-parts: "goose" (IEC-61850/GOOSE) matches inside "Mongoose Web
    Server"; "apdu" (IEC-104) matches inside "heapdump". Both were found
    live in this project's own validation-set construction. `\\b` word
    boundaries fix both while still matching a keyword like "cip" as its
    own token (e.g. "Common Industrial Protocol (CIP)") and multi-word
    phrases like "function code" (space is already a non-word boundary).
    """
    return re.search(rf"\b{re.escape(keyword.lower())}\b", lower_text) is not None


def classify(text: str, rules: list[ProtocolRule]) -> list[ClassificationResult]:
    """Classify a piece of text (e.g. a CVE description) against protocol rules.

    Pure function: no I/O, no database access. For each rule, does a
    case-insensitive substring search for any of its keywords; the first
    keyword found is the primary evidence. If found, also checks for a
    function-code-shaped regex match corroborating via that protocol
    function_codes table, and a standalone port-number mention -- both
    appended to the evidence string, never treated as a match on their own.

    Args:
        text: Free text to classify (a CVE description).
        rules: Protocol rules, e.g. from load_protocol_rules().

    Returns:
        One ClassificationResult per protocol with at least one keyword
        match. A single CVE description can match multiple protocols.
    """
    if not text:
        return []

    lower = text.lower()
    results: list[ClassificationResult] = []

    function_code_hits = {int(m.group(1)) for m in _FUNCTION_CODE_RE.finditer(lower)}

    for rule in rules:
        matched_keyword = next(
            (kw for kw in rule.keywords if _keyword_matches(kw, lower)), None
        )
        if matched_keyword is None:
            continue

        evidence = f"keyword:{matched_keyword}"

        for code in sorted(function_code_hits & rule.function_codes.keys()):
            evidence += f"+function_code:{code}"

        for port in rule.ports:
            if _port_appears(lower, port):
                evidence += f"+port:{port}"

        results.append(ClassificationResult(protocol_name=rule.name, evidence=evidence))

    return results


def _protocol_id(name: str) -> str:
    """Slugify a protocol name into a stable node id, e.g. EtherNet/IP -> ethernet_ip."""
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return f"protocol-{slug}"


def run(
    conn,
    rules_path: Path | str = "config/protocols.yaml",
    source_prefix: str = "nvd-",
) -> dict:
    """Classify every vuln node description and write involves edges.

    Args:
        conn: An open sqlite3.Connection from store.get_connection.
        rules_path: Path to config/protocols.yaml.
        source_prefix: Prefix + CVE id used to look up the source row that
            the description came from (the NVD collector writes one
            nvd-{cve} source row per CVE it enriches).

    Returns:
        Summary dict: vulns examined, vulns with a description, vulns with
        CSAF product-tree text, edges written, distinct protocols matched,
        and vulns skipped for lacking a matching source row (a real
        data-inconsistency signal worth surfacing rather than silently
        swallowing).
    """
    rules = load_protocol_rules(rules_path)
    fetched_at = datetime.now(UTC).isoformat()

    # Re-runnable: clear prior involves edges first, since insert_edge is
    # upsert-by-id and would otherwise leave stale edges from a rule that
    # no longer matches (e.g. after a classifier bug fix) sitting in the
    # graph forever.
    store.delete_edges_by_type(conn, "involves")

    vulns = store.get_all_vuln_nodes(conn)
    vulns_with_description = 0
    vulns_with_csaf_product_text = 0
    edges_written = 0
    protocols_matched: set[str] = set()
    missing_source_skips = 0

    def _write_matches(
        *, cve: str, matches: list[ClassificationResult], source_id: str | None,
        source_kind: str,
    ) -> None:
        nonlocal edges_written, missing_source_skips
        if not matches:
            return
        if source_id is None or not store.source_exists(conn, source_id):
            logger.warning(
                "protocol classifier: vuln %s has %s text but no matching "
                "source row %r; skipping involves edge(s) for it (data "
                "inconsistency -- text should always come with its own "
                "source row)",
                cve,
                source_kind,
                source_id,
            )
            missing_source_skips += 1
            return
        for match in matches:
            protocol_id = _protocol_id(match.protocol_name)
            store.insert_node(
                conn,
                id=protocol_id,
                type="protocol",
                label=match.protocol_name,
                attrs=json.dumps({"name": match.protocol_name}),
                created_at=fetched_at,
            )
            store.insert_edge(
                conn,
                id=f"{cve}--involves--{protocol_id}--{source_kind}",
                src_id=cve,
                dst_id=protocol_id,
                type="involves",
                source_id=source_id,
                note=f"{match.evidence}+source:{source_kind}",
            )
            edges_written += 1
            protocols_matched.add(match.protocol_name)

    for vuln in vulns:
        attrs = vuln.get("attrs") or {}
        description = attrs.get("description")
        csaf_product_text = attrs.get("csaf_product_text")
        cve = vuln["id"]

        if description:
            vulns_with_description += 1
            _write_matches(
                cve=cve,
                matches=classify(description, rules),
                source_id=f"{source_prefix}{cve}",
                source_kind="nvd",
            )

        if csaf_product_text:
            vulns_with_csaf_product_text += 1
            _write_matches(
                cve=cve,
                matches=classify(csaf_product_text, rules),
                source_id=store.get_describing_advisory_source_id(conn, cve),
                source_kind="csaf",
            )

    return {
        "vulns_examined": len(vulns),
        "vulns_with_description": vulns_with_description,
        "vulns_with_csaf_product_text": vulns_with_csaf_product_text,
        "edges_written": edges_written,
        "protocols_matched": len(protocols_matched),
        "vulns_skipped_missing_source": missing_source_skips,
    }
