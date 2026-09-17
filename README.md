# STRATA — OT/ICS Threat-Capability Tracking Pipeline

**Week 1 "spine" + Week 2 "breadth."** A local-only, zero-cost collection
pipeline that pulls public OT/ICS vulnerability advisories, exploitation
signals (NVD, EPSS, PoC-in-GitHub, Exploit-DB, Nuclei, Metasploit), MITRE
ATT&CK technique reference data, and a hand-curated threat-group corpus
into a provenance-tracked SQLite graph, and prints collection stats. This
is the first two of four build phases described in
`strata-engineering-spec.md`; see that document for the full architecture,
later-week scope (enrichment, hunts, exports, Streamlit UI), and design
rationale.

## Why this exists — "RSS is dead"

CISA retired its ICS advisory and KEV RSS/XML feeds in May 2025 with no
replacement. Any pipeline still pointed at
`us-cert.cisa.gov/ics/advisories/advisories.xml` is reading a dead feed.
The machine-readable path today is the CSAF (Common Security Advisory
Framework) JSON corpus published at `github.com/cisagov/CSAF`, plus the KEV
catalog JSON. This is a design decision reflecting where CISA's tooling
actually is now, not a workaround or a limitation.

## What's built (Week 1 + Week 2)

- `net.py` — an egress-allowlisted `httpx` client with per-host rate
  limiting, conditional-request caching (ETag / Last-Modified), on-disk
  snapshotting with SHA-256 provenance, and a strict `--offline` mode that
  makes zero network calls.
- `model/schema.sql` + `model/store.py` — SQLite graph (`source`, `node`,
  `edge`, `metric_observation`) with the **non-negotiable provenance
  constraint**: every edge must cite a valid, existing `source` row, or the
  insert raises `sqlite3.IntegrityError`.
- `collect/cisa_kev.py` — CISA Known Exploited Vulnerabilities catalog
  collector.
- `collect/cisa_csaf.py` — CISA CSAF advisory collector, discovering the
  most recent N advisory files via the GitHub Git Trees API (see below).
- `collect/nvd.py` — enriches known `vuln` nodes with CVSS/CWE/CPE data
  from the NVD `cve/2.0` API; `normalize/cpe.py` parses CPE 2.3 strings
  into `product`/`vendor` nodes and `affects`/`made_by` edges.
- `collect/attack.py` — MITRE ATT&CK enterprise + ICS `technique` nodes.
- `collect/epss.py` — FIRST.org EPSS scores as `metric_observation` rows.
- `collect/poc_github.py`, `collect/exploitdb.py`, `collect/nuclei.py`,
  `collect/metasploit.py` — weaponization-timing signal collectors,
  writing into a dedicated `signal` table (not the node/edge graph).
- `normalize/models.py` + `normalize/corpus.py` — pydantic-validated
  corpus loader: `corpus/citations.yaml` + `corpus/groups/*.yaml` ->
  `group`/`tool`/`vuln`/`technique`/`sector`/`geo` nodes and their edges,
  with fail-loud citation validation and stub-node creation for
  hands-off-to targets that lack their own corpus entry.
- `cli.py` — `strata collect --source {kev,csaf,nvd,attack,epss,
  poc-github,exploitdb,nuclei,metasploit,all}`, `strata stats`, and
  `strata corpus load`.

## CSAF file-discovery assumption (read this before relying on it)

`github.com/cisagov/CSAF` has no stable "latest N advisories" API endpoint.
This collector enumerates the whole repository tree via
`GET api.github.com/repos/cisagov/CSAF/git/trees/main?recursive=1`, filters
blob paths down to the current calendar year's advisory JSON files, sorts
them, and takes the most recent `N=25` (a constant in `cisa_csaf.py`) by
fetching each one's raw content from `raw.githubusercontent.com`. `--since`
filtering on CSAF is therefore **best-effort and client-side**, applied
only to the N-file sample already fetched — it cannot reach further back
than that sample. This is a known Week 1 limitation; a more thorough
backfill (e.g. paging further back or using the ROLIE feed index) is
future-week scope.

## Provenance granularity

- One `source` row per CSAF advisory file fetched.
- One shared `source` row per KEV fetch (the KEV catalog is a single JSON
  payload covering all entries).

## Running it

```bash
uv sync
uv run strata collect --source all
uv run strata corpus load
uv run strata stats
```

Re-run fully offline from cache (no network calls):

```bash
uv run strata collect --source all --offline
```

Run tests / lint:

```bash
uv run pytest -v
uv run ruff check .
```

`make test`, `make collect` wrap the equivalent `uv run` commands. GNU Make
may not be installed on Windows — `uv run <cmd>` is the primary supported
interface; see `Makefile` for details.

## Current scope — Week 1 + Week 2

Implemented: egress-guarded fetch/cache layer, SQLite graph schema with the
provenance constraint (plus the Week 2 `signal` table and merge-upsert
`node.attrs` semantics), KEV + CISA CSAF + NVD + ATT&CK + EPSS collectors,
four weaponization-signal collectors (PoC-in-GitHub, Exploit-DB, Nuclei,
Metasploit), a hand-curated corpus loader, `strata collect`, `strata
stats`, and `strata corpus load`.

**Not implemented yet** (later weeks per the spec): vendor-PSIRT
collectors, `strata build` (normalize + load + enrich), the protocol
classifier, Purdue mapping, the weaponization timeline (`enrich/
timeline.py` -- this is exactly what the new `signal` table and PoC/
Exploit-DB/Nuclei/Metasploit data feed), adversary consensus scoring, the
ten hunts and `strata hunt`, `strata export` (Storm/STIX/JSON-LD), `strata
graph show`, and the Streamlit UI. `strata build` is intentionally
**omitted from the CLI** (not stubbed), so `--help` doesn't advertise
functionality that doesn't exist yet.

net.py's rate limiter is source-agnostic (keyed by host, configured via
`config/sources.toml`). See `SOURCES.md` for a discovered gap: it enforces
per-request spacing, not a rolling-window budget, which does not match
GitHub's real unauthenticated 60-requests/hour REST API cap -- the
`nuclei`/`metasploit` collectors handle this gracefully (see SOURCES.md).

## Deliberately excluded (project-wide, all weeks)

Shodan, Censys, VirusTotal (beyond metadata-only free tier), Recorded
Future, Joe Sandbox. All either paid, rate-crippled, or require handling
executable samples, which this project never does. See
`strata-engineering-spec.md` §4.2.

## Legal / ethical framing

This repository reproduces no proprietary threat-intelligence report
content. Threat group names (where used in later weeks) are public
nomenclature with attribution to the naming organization. No active
scanning of any kind is performed, ever — only HTTPS GETs to a static
allowlist of public feed hosts. No malware samples are downloaded, stored,
or executed.

See `SECURITY.md` for the egress-allowlist model and secrets handling, and
`SOURCES.md` for per-source licensing/terms and cadence.
