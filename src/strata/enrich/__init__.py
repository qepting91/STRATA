"""Enrichment package: derived datasets computed over the existing graph.

Each module (protocol, purdue, consensus, timeline) exposes a pure,
unit-testable classification/computation function plus a run(conn, ...)
entry point that reads from and writes into the graph via strata.model.store.
"""
