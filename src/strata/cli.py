"""STRATA command-line interface.

Week 1 scope: `strata collect` and `strata stats`. `strata build` is
intentionally not implemented and not stubbed here, so `--help` does not
advertise functionality that does not exist yet.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

import typer

from strata import net
from strata.collect.base import Collector
from strata.collect.cisa_csaf import CISACSAFCollector
from strata.collect.cisa_kev import CISAKEVCollector
from strata.model import store
from strata.settings import get_settings

app = typer.Typer(help="STRATA - local-only OT/ICS threat-capability tracking pipeline.")


class SourceChoice(StrEnum):
    """Valid values for `strata collect --source`."""

    kev = "kev"
    csaf = "csaf"
    all = "all"


def _build_collectors(choice: SourceChoice, net_client: net.NetClient) -> list[Collector]:
    if choice == SourceChoice.kev:
        return [CISAKEVCollector(net_client)]
    if choice == SourceChoice.csaf:
        return [CISACSAFCollector(net_client)]
    return [CISAKEVCollector(net_client), CISACSAFCollector(net_client)]


_SOURCE_OPTION = typer.Option(SourceChoice.all, "--source", help="Which source(s) to collect.")
_SINCE_OPTION = typer.Option(
    None, "--since", help="ISO date (YYYY-MM-DD); best-effort client-side filter."
)
_OFFLINE_OPTION = typer.Option(
    False, "--offline", help="Serve strictly from the on-disk cache; zero network calls."
)


@app.command()
def collect(
    source: SourceChoice = _SOURCE_OPTION,
    since: str | None = _SINCE_OPTION,
    offline: bool = _OFFLINE_OPTION,
) -> None:
    """Run one or more collectors and load results into the local graph."""
    settings = get_settings()
    since_date: date | None = None
    if since is not None:
        try:
            since_date = datetime.strptime(since, "%Y-%m-%d").date()
        except ValueError as exc:
            raise typer.BadParameter(f"--since must be YYYY-MM-DD, got {since!r}") from exc

    conn = store.get_connection(settings.db_path)
    net_client = net.NetClient(
        allowlist_path=settings.allowlist_path,
        sources_config_path=settings.sources_config_path,
        data_dir=settings.data_dir,
    )

    collectors = _build_collectors(source, net_client)

    typer.echo(f"{'source':<12} {'sources':>8} {'nodes':>8} {'edges':>8}")
    typer.echo("-" * 40)
    for collector in collectors:
        collector.since = since_date
        summary = collector.run(conn, offline=offline)
        typer.echo(
            f"{summary['source']:<12} {summary['sources']:>8} "
            f"{summary['nodes']:>8} {summary['edges']:>8}"
        )

    net_client.close()
    conn.close()


@app.command()
def stats() -> None:
    """Print node/edge/source counts by type from the local graph."""
    settings = get_settings()
    conn = store.get_connection(settings.db_path)

    node_counts = store.count_nodes_by_type(conn)
    edge_counts = store.count_edges_by_type(conn)
    source_count = store.count_sources(conn)
    latest_fetches = store.latest_fetch_times(conn)

    typer.echo("Nodes by type:")
    if not node_counts:
        typer.echo("  (none)")
    for node_type, count in node_counts.items():
        typer.echo(f"  {node_type:<12} {count}")

    typer.echo("\nEdges by type:")
    if not edge_counts:
        typer.echo("  (none)")
    for edge_type, count in edge_counts.items():
        typer.echo(f"  {edge_type:<15} {count}")

    typer.echo(f"\nTotal source rows: {source_count}")

    typer.echo("\nLatest fetch per source:")
    if not latest_fetches:
        typer.echo("  (none)")
    for name, latest in latest_fetches.items():
        typer.echo(f"  {name:<12} {latest}")

    conn.close()


if __name__ == "__main__":
    app()
