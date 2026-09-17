"""STRATA command-line interface.

`strata collect`, `strata stats`, `strata corpus load` (Week 1-2), and
`strata build` (Week 3 -- corpus load + all enrichment passes in one
command, closing the gap intentionally left open since Week 1).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime
from enum import StrEnum

import typer

from strata import net
from strata.collect.attack import ATTACKCollector
from strata.collect.base import Collector
from strata.collect.cisa_csaf import CISACSAFCollector
from strata.collect.cisa_kev import CISAKEVCollector
from strata.collect.epss import EPSSCollector
from strata.collect.exploitdb import ExploitDBCollector
from strata.collect.metasploit import MetasploitCollector
from strata.collect.nuclei import NucleiCollector
from strata.collect.nvd import NVDCollector
from strata.collect.poc_github import PoCGitHubCollector
from strata.enrich import consensus as enrich_consensus
from strata.enrich import protocol as enrich_protocol
from strata.enrich import purdue as enrich_purdue
from strata.enrich import timeline as enrich_timeline
from strata.model import store
from strata.normalize.corpus import CorpusLoadError, load_corpus
from strata.settings import Settings, get_settings

app = typer.Typer(help="STRATA - local-only OT/ICS threat-capability tracking pipeline.")


class SourceChoice(StrEnum):
    """Valid values for `strata collect --source`."""

    kev = "kev"
    csaf = "csaf"
    nvd = "nvd"
    attack = "attack"
    epss = "epss"
    poc_github = "poc-github"
    exploitdb = "exploitdb"
    nuclei = "nuclei"
    metasploit = "metasploit"
    all = "all"


# Registry mapping a source-name string to a zero-or-one-arg collector
# constructor. Replaces a growing if/elif so adding a new collector is a
# one-line addition here plus a new SourceChoice member -- no branching
# logic to touch. `all` is handled separately (it is "every registry entry
# in a stable order"), not itself a registry key.
_COLLECTOR_REGISTRY: dict[str, Callable[[net.NetClient, Settings], Collector]] = {
    SourceChoice.kev: lambda nc, settings: CISAKEVCollector(nc),
    SourceChoice.csaf: lambda nc, settings: CISACSAFCollector(nc),
    SourceChoice.nvd: lambda nc, settings: NVDCollector(
        nc,
        api_key=settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None,
    ),
    SourceChoice.attack: lambda nc, settings: ATTACKCollector(nc),
    SourceChoice.epss: lambda nc, settings: EPSSCollector(nc),
    SourceChoice.poc_github: lambda nc, settings: PoCGitHubCollector(nc),
    SourceChoice.exploitdb: lambda nc, settings: ExploitDBCollector(nc),
    SourceChoice.nuclei: lambda nc, settings: NucleiCollector(nc),
    SourceChoice.metasploit: lambda nc, settings: MetasploitCollector(nc),
}

# Stable execution order for `--source all`: cheap/foundational sources
# first (KEV/CSAF seed vuln nodes), then NVD/ATT&CK/EPSS enrichment (NVD
# and EPSS depend on vuln nodes already existing), then the signal
# collectors last (independent of the graph).
_ALL_ORDER = [
    SourceChoice.kev,
    SourceChoice.csaf,
    SourceChoice.attack,
    SourceChoice.nvd,
    SourceChoice.epss,
    SourceChoice.poc_github,
    SourceChoice.exploitdb,
    SourceChoice.nuclei,
    SourceChoice.metasploit,
]


def _build_collectors(
    choice: SourceChoice, net_client: net.NetClient, settings: Settings
) -> list[Collector]:
    if choice == SourceChoice.all:
        return [_COLLECTOR_REGISTRY[c](net_client, settings) for c in _ALL_ORDER]
    return [_COLLECTOR_REGISTRY[choice](net_client, settings)]


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
    # NVD's documented keyed tier (50 req/30s) is much faster than the
    # unconditional keyless-tier default baked into config/sources.toml
    # (5 req/30s -- see the comment there). Since NetClient is shared
    # across every collector in this run, the override is scoped to NVD's
    # host only and is a no-op for every other collector/host.
    rate_limit_overrides: dict[str, tuple[int, float]] | None = None
    if settings.nvd_api_key is not None:
        rate_limit_overrides = {"services.nvd.nist.gov": (50, 30.0)}
    net_client = net.NetClient(
        allowlist_path=settings.allowlist_path,
        sources_config_path=settings.sources_config_path,
        data_dir=settings.data_dir,
        rate_limit_overrides=rate_limit_overrides,
    )

    collectors = _build_collectors(source, net_client, settings)

    typer.echo(
        f"{'source':<12} {'sources':>8} {'nodes':>8} {'edges':>8} "
        f"{'signals':>8} {'metrics':>8}"
    )
    typer.echo("-" * 62)
    for collector in collectors:
        collector.since = since_date
        summary = collector.run(conn, offline=offline)
        typer.echo(
            f"{summary['source']:<12} {summary['sources']:>8} "
            f"{summary['nodes']:>8} {summary['edges']:>8} "
            f"{summary.get('signals', 0):>8} {summary.get('metric_observations', 0):>8}"
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
    signal_counts = store.count_signals_by_source(conn)
    metric_counts = store.count_metric_observations_by_name(conn)

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

    typer.echo("\nSignals by source:")
    if not signal_counts:
        typer.echo("  (none)")
    for signal_source, count in signal_counts.items():
        typer.echo(f"  {signal_source:<12} {count}")

    typer.echo("\nMetric observations by name:")
    if not metric_counts:
        typer.echo("  (none)")
    for metric_name, count in metric_counts.items():
        typer.echo(f"  {metric_name:<15} {count}")

    typer.echo(f"\nTotal source rows: {source_count}")

    typer.echo("\nLatest fetch per source:")
    if not latest_fetches:
        typer.echo("  (none)")
    for name, latest in latest_fetches.items():
        typer.echo(f"  {name:<12} {latest}")

    # Week 3 additions: `involves` edges surface via edge_counts above with
    # no code change needed there. Purdue-level breakdown and top-N
    # consensus products are new here.
    products = store.get_all_products(conn)
    level_counts: dict[str, int] = {}
    for product in products:
        attrs = product.get("attrs") or {}
        level = attrs.get("purdue_level")
        key = str(level) if level is not None else "(unmapped)"
        level_counts[key] = level_counts.get(key, 0) + 1

    typer.echo("\nPurdue level breakdown (product count by level):")
    if not level_counts:
        typer.echo("  (none)")
    for level, count in sorted(level_counts.items()):
        typer.echo(f"  {level:<12} {count}")

    consensus_ranked = enrich_consensus.run(conn)
    typer.echo("\nTop 5 products by adversary consensus (distinct groups):")
    if not consensus_ranked:
        typer.echo("  (none)")
    for row in consensus_ranked[:5]:
        typer.echo(f"  {row['product_id']:<30} groups={row['group_count']}")

    conn.close()


corpus_app = typer.Typer(help="Load the hand-curated threat-group corpus into the graph.")
app.add_typer(corpus_app, name="corpus")


@corpus_app.command("load")
def corpus_load(
    corpus_dir: str = typer.Option("corpus", "--corpus-dir", help="Corpus root directory."),
) -> None:
    """Load corpus/citations.yaml + corpus/groups/*.yaml into the local graph."""
    settings = get_settings()
    conn = store.get_connection(settings.db_path)

    try:
        summary = load_corpus(conn, corpus_dir=corpus_dir)
    except CorpusLoadError as exc:
        conn.close()
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"Nodes written:   {summary.nodes}")
    typer.echo(f"Edges written:   {summary.edges}")
    typer.echo(f"Sources ensured: {summary.sources}")
    typer.echo(f"Groups fully loaded ({len(summary.groups_loaded)}): "
               f"{', '.join(summary.groups_loaded) or '(none)'}")
    typer.echo(f"Groups stub-created ({len(summary.groups_stubbed)}): "
               f"{', '.join(summary.groups_stubbed) or '(none)'}")

    conn.close()


@app.command()
def build(
    corpus_dir: str = typer.Option("corpus", "--corpus-dir", help="Corpus root directory."),
) -> None:
    """Normalize + load + enrich: corpus load, then all enrichment passes.

    Matches spec section 11's `strata build # normalize + load + enrich`
    exactly. Runs, in order: corpus load (idempotent, safe to re-run),
    enrich.protocol.run, enrich.purdue.run, enrich.timeline.run, then
    enrich.consensus.run (whose output is a ranking to print, not a graph
    mutation -- it writes nothing back to the DB).
    """
    settings = get_settings()
    conn = store.get_connection(settings.db_path)

    try:
        corpus_summary = load_corpus(conn, corpus_dir=corpus_dir)
    except CorpusLoadError as exc:
        conn.close()
        raise typer.BadParameter(str(exc)) from exc

    typer.echo("Corpus load:")
    typer.echo(f"  nodes={corpus_summary.nodes} edges={corpus_summary.edges} "
               f"sources={corpus_summary.sources}")

    protocol_summary = enrich_protocol.run(conn)
    typer.echo("Protocol classifier:")
    typer.echo(f"  {protocol_summary}")

    purdue_summary = enrich_purdue.run(conn)
    typer.echo("Purdue mapping:")
    typer.echo(f"  {purdue_summary}")

    timeline_summary = enrich_timeline.run(conn)
    typer.echo("Weaponization timeline:")
    typer.echo(f"  {timeline_summary}")

    consensus_ranked = enrich_consensus.run(conn)
    typer.echo("Adversary consensus (top 5 by distinct-group count):")
    for row in consensus_ranked[:5]:
        typer.echo(f"  {row['product_id']:<30} groups={row['group_count']}")

    conn.close()


if __name__ == "__main__":
    app()
