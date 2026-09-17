# STRATA — OT/ICS Threat-Capability Tracking Pipeline

**Weeks 1-3 of 4 ("spine" + "breadth" + "the original work").** A
local-only, zero-cost pipeline that pulls public OT/ICS vulnerability
advisories, exploitation signals (NVD, EPSS, PoC-in-GitHub, Exploit-DB,
Nuclei, Metasploit), MITRE ATT&CK technique reference data, and a
hand-curated 8-group threat corpus into a provenance-tracked SQLite
graph, then enriches it: an ICS protocol classifier, Purdue-level
product mapping, a weaponization timeline, and adversary-consensus
scoring. See `strata-engineering-spec.md` for the full architecture,
Week 4 scope (hunts, exports, Streamlit UI), and design rationale.

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
  corpus loader: `corpus/citations.yaml` + `corpus/groups/*.yaml` (all 8
  spec-listed groups now authored: SYLVANITE, VOLTZITE, KAMACITE,
  ELECTRUM, AZURITE, PYROXENE, BAUXITE, PARISITE) -> `group`/`tool`/
  `vuln`/`technique`/`sector`/`geo` nodes and their edges, with fail-loud
  citation validation and stub-node creation for hands-off-to targets
  that lack their own corpus entry (currently: `magnallium`, referenced
  only via PARISITE's handoff).
- `enrich/protocol.py` — rule-based ICS protocol classifier
  (`config/protocols.yaml`: Modbus/S7comm/IEC-104/DNP3/IEC-61850/
  EtherNet-IP/OPC-UA/BACnet/MQTT) over NVD description text, writing
  `vuln -[:involves]-> protocol` edges with an evidence note. **Real,
  measured precision/recall on a 200-CVE hand-labeled validation set:
  precision = 1.000 (3/3), recall = 1.000 (3/3)** — see "Protocol
  classifier validation" below for the methodology and an honest caveat
  about what a sample this small can and can't tell you.
- `enrich/purdue.py` — maps `product` nodes to a Purdue level/class via
  `config/purdue_map.yaml`, merged into the product's `attrs`.
- `enrich/timeline.py` — the weaponization timeline: `t_disclosed`
  (earliest of vendor CSAF/NVD/KEV dates), PoC-corroboration-tiered
  `t_first_poc`, derived intervals (`disclosure_to_poc_days`,
  `poc_to_kev_days`, `detection_lag_days`, `patch_available_at_kev`) as
  `metric_observation` rows.
- `enrich/consensus.py` — adversary-consensus scoring: for each product,
  the count of distinct groups whose `exploits` edges reach a CVE that
  `affects` it (a 2-hop SQL join, not a graph library — see the spec's
  own §7.1 point that a 4-edge join doesn't need one).
- `cli.py` — `strata collect --source {kev,csaf,nvd,attack,epss,
  poc-github,exploitdb,nuclei,metasploit,all}`, `strata stats`, `strata
  corpus load`, and **`strata build`** (corpus load + all four
  enrichment passes in one command — implemented this week, closing a
  gap left open since Week 1 because `normalize`/`enrich` didn't exist
  yet).

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

## Protocol classifier validation

The spec's testing table calls for "a 200-CVE hand-labelled validation
set; assert precision >= 0.85." This was built for real, against the
real graph, not a synthetic fixture — but the corpus's actual base rate
of ICS-protocol-specific CVEs turned out to be very low: **only 3 of
1,790 known CVEs** (KEV/CSAF/NVD-sourced, overwhelmingly enterprise
edge-device CVEs like Ivanti/Fortinet/Cisco appliances) trigger any
protocol keyword match at all. The 200-CVE sample is therefore
**stratified, not random**: all 3 keyword-matching CVEs plus 197 randomly
sampled non-matching CVEs, so both precision (checking the matched set)
and recall (checking a large sample of the unmatched set for anything
the classifier missed) are measurable at all. An independent reviewer —
explicitly instructed not to just re-run the same keyword rule, which
would be circular — read all 200 descriptions in full. Result: **3/3
true positives, 0 false positives found in the 197 negatives** →
precision = recall = 1.000. Both clear the spec's 0.85 target, but on
n=3 positives — this is reported honestly as a small-sample result, not
dressed up as more statistically confident than it is. See
`tests/fixtures/protocol_validation_labels.json` (`labeling_summary`
field) for the full methodology and the reviewer's caveats, and
`tests/test_enrich_protocol_validation_set.py` for the test that
reproduces these exact numbers against the real classifier.

**Real bugs found and fixed during this validation work** (documented
here rather than quietly folded in, since surfacing your own errors is
this project's whole stated ethos — spec §16): the classifier originally
used plain substring matching with no word boundaries, so "Mongoose Web
Server" matched the IEC-61850 keyword "goose", and "heapdump" matched
the IEC-104 keyword "apdu" — both fixed with `\b`-anchored regex
matching. Separately, `enrich/protocol.py`'s `run()` only ever *inserted*
`involves` edges (upsert-by-id) and never cleared stale ones, so a CVE
that used to match under the buggy rule kept its edge forever even after
the fix — fixed by clearing all `involves` edges at the start of every
run before recomputing (`store.delete_edges_by_type`). The identical
staleness bug was also found and fixed in `enrich/timeline.py`'s derived
`metric_observation` rows (`store.delete_metric_observations_by_names`),
and a latent (currently unreachable, but real) bug in
`enrich/purdue.py`'s slug construction that would have rendered a `None`
vendor/product as the literal string `"none"` was fixed defensively.

## Provenance granularity

- One `source` row per CSAF advisory file fetched.
- One shared `source` row per KEV fetch (the KEV catalog is a single JSON
  payload covering all entries).

## Running it

```bash
uv sync
uv run strata collect --source all
uv run strata build      # corpus load + protocol/purdue/timeline/consensus enrichment
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

## Current scope — Week 1 + Week 2 + Week 3

Implemented: egress-guarded fetch/cache layer (with a per-host
rate-limit-override mechanism so an NVD API key actually unlocks the
faster documented tier), SQLite graph schema with the provenance
constraint (plus `signal`, `metric_observation`, and `edge.note`),
KEV + CISA CSAF + NVD + ATT&CK + EPSS collectors, four
weaponization-signal collectors, a hand-curated 8-group corpus loader,
the protocol classifier + Purdue mapping + weaponization timeline +
adversary consensus enrichment passes, `strata collect`, `strata stats`,
`strata corpus load`, and `strata build`.

**Known, documented scope reductions** (not silently dropped):
- The protocol classifier only reads NVD description text; the spec's
  other stated input (CSAF product-tree text) is out of scope since the
  CSAF collector doesn't extract product-tree text at all yet.
- `t_group_observed`/`disclosure_to_group_use` is not computed — the
  corpus format has no `first_seen` date on a group's `exploits` entries.
- PoC-corroboration only distinguishes `high`/`moderate` tiers (the
  spec's fuller `moderate` definition needs a per-repo commit/file-count
  signal `poc_github.py`'s `meta` doesn't collect) — `t_first_poc` and
  `t_first_poc_claimed` will therefore never diverge under current logic,
  which is a real limitation of the corroboration model worth knowing
  about if you rely on that specific comparison.
- Adversary consensus's `overlaps_with`-based cluster-collapsing is a
  no-op — no `overlaps_with` edges exist in the corpus yet.

**Not implemented yet** (Week 4 per the spec): vendor-PSIRT collectors,
the ten hunts and `strata hunt`, `strata export` (Storm/STIX/JSON-LD),
`strata graph show`, and the Streamlit UI.

net.py's rate limiter is source-agnostic (keyed by host, configured via
`config/sources.toml`, with a per-call override mechanism added this
week). See `SOURCES.md` for a discovered gap: it enforces per-request
spacing, not a rolling-window budget, which does not match GitHub's real
unauthenticated 60-requests/hour REST API cap -- the `nuclei`/
`metasploit` collectors handle this gracefully (see SOURCES.md). NVD
itself also enforces a tighter short-burst limit than its documented
50/30s rolling budget — `net.py` now retries a `429` with bounded
exponential backoff honoring `Retry-After`, discovered live while running
the real full NVD backfill this week.

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
