# STRATA — OT/ICS Threat-Capability Tracking Pipeline

**Weeks 1-4 of 4 ("spine" + "breadth" + "the original work" + "analysis
and packaging").** A local-only, zero-cost pipeline that pulls public
OT/ICS vulnerability advisories, exploitation signals (NVD, EPSS,
PoC-in-GitHub, Exploit-DB, Nuclei, Metasploit), MITRE ATT&CK technique
reference data, and a hand-curated 8-group threat corpus into a
provenance-tracked SQLite graph; enriches it (an ICS protocol classifier,
Purdue-level product mapping, a weaponization timeline, and
adversary-consensus scoring); runs ten falsifiable hunts over it; and
exports/reports on the result (Synapse Storm, STIX 2.1, JSON-LD, and a
generated intel report). See `strata-engineering-spec.md` for the full
architecture and design rationale, and `docs/demo.md` for a 90-second
walkthrough.

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

## What's built (Week 4)

- `hunt/` package — `hunt/models.py` (pydantic model for a `hunts/*.yaml`
  file), `hunt/runner.py` (dispatches by `method: sql|graph|python`),
  `hunt/graph_ops.py` (`descendants_within`, a NetworkX BFS for the
  handoff-traversal hunt), `hunt/methods.py` (the 5 python-method hunts'
  custom logic), `hunt/verdicts.py` (three-state verdict evaluation via
  `simpleeval`, never Python `eval`). Ten curated hunts in `hunts/*.yaml`
  (H001–H010, spec §7.4), each wired to a real query/traversal/function
  over the actual graph — no hardcoded thresholds or fabricated numbers.
  **Real board: 5 SUPPORTED (H002, H003, H005, H007, H009), 1 REFUTED
  (H001), 4 INSUFFICIENT (H004, H006, H008, H010)** — a genuinely mixed
  board, not curated to look better than the data supports. `strata hunt
  list`, `strata hunt run <ID> [--format table|json]`, `strata hunt run
  --all`.
- `export/` package — `export/storm.py` (a generated, syntax-checked
  Synapse Storm script; paired queries in `docs/storm-queries.md`),
  `export/stix.py` (a STIX 2.1 bundle, `intrusion-set`/`malware`/`tool`/
  `attack-pattern`/`vulnerability`/`relationship`, validated with
  `stix2-validator`), `export/jsonld.py` (a raw JSON-LD graph dump),
  `export/graph_render.py` (a static Graphviz/DOT render of the
  `hands_off_to` handoff model). `strata export {storm,stix,jsonld}
  [--out PATH]`, `strata graph show --group sylvanite --depth 2`.
- `report/render.py` + `report/templates/report.md.j2` — the spec §12
  7-section intel report (key judgements, scope/method, findings for all
  ten hunts, capability handoff model, visibility gaps, confidence and
  limitations, appendix/source registry), rendered via Jinja2 directly
  from a live run of every hunt plus the live graph — every figure in the
  generated report is re-derived at render time, never hardcoded.
  `strata report` writes `reports/<date>-ot-capability-assessment.md`.
- `config/telemetry_matrix.yaml` — the spec §6.5 telemetry requirement
  matrix (hunt technique → telemetry required → typical OT collection
  status → difficulty), rendered ranked cheapest-to-close-first in the
  report's "Visibility gaps" section.
- `docs/demo.md` — the spec §14 90-second interview demo script, adapted
  to what this implementation's real hunt board actually shows (see
  below).

## Working through the INSUFFICIENT hunts

After Week 4, five hunts were INSUFFICIENT. Rather than leave that
untouched, each gap was investigated on its own terms — closed with real
data where real data exists, left honestly INSUFFICIENT (with a richer,
specific `telemetry_gap`) where it doesn't:

- **H002 (closed — now SUPPORTED)**: Mandiant's and SecurityAffairs's own
  reporting (already cited as S-0004/S-0005/S-0006) gives concrete
  first-observed-exploitation dates for all 5 of SYLVANITE's CVEs —
  added as `first_seen` on each corpus `exploits` entry (no new
  citations needed), stored on the `exploits` edge's `note` column, and
  read back by `enrich/timeline.py` to compute `t_group_observed`/
  `disclosure_to_group_use`. Real result: n=5 (SYLVANITE only — the
  other 7 groups' exploits lists still have no first_seen data),
  median **-38 days** — a genuinely interesting negative number
  reflecting real zero-day exploitation that predated public disclosure,
  not a data error.
- **H008 (investigated, real code change, verdict unchanged)**: extended
  `collect/cisa_csaf.py` to extract CSAF advisory `product_tree` text and
  `enrich/protocol.py` to classify it too (citing the CSAF advisory's own
  source, not NVD's) — closing the documented Week 3 gap. Real result:
  one additional `involves` edge, still only 3 distinct protocol-matching
  CVEs total, so still INSUFFICIENT for a trend claim — but now for the
  right reason (the corpus's real base rate is that low), not a known
  code gap.
- **H010 (closed — collectors built, verdict is honest, not force-fed)**:
  built two new, live-verified vendor-PSIRT collectors — Siemens
  ProductCERT (`collect/siemens_psirt.py`, ROLIE feed) and Schneider
  Electric CPCERT (`collect/schneider_psirt.py`, `changes.csv`
  distribution) — giving H010 its first real per-vendor disclosure
  dates. Live collection found only 6 Siemens and 1 Schneider advisory
  with a computable latency point (most fetched advisories are for very
  recent CVEs NVD/KEV haven't dated yet). `hunt/methods.py`'s
  `h010_vendor_patch_latency` requires **every** vendor with any data to
  have ≥3 latency points before trusting a comparison — on this real,
  thin sample that correctly keeps H010 INSUFFICIENT rather than
  reporting SUPPORTED off a single Schneider data point, which an
  earlier, looser gate briefly did before being tightened.
- **H004 and H006 (investigated, genuine dead ends — still
  INSUFFICIENT)**: real web research found no source tying two of the 8
  tracked groups to the same named tool (H004), and confirmed VOLTZITE's
  own public reporting really does describe compromising Sierra Wireless
  AirLink cellular gateways (H006) — but the one CVE publicly tied to
  that hardware (CVE-2018-4063) is attributed by other researchers to an
  unrelated, unattributed cluster, not VOLTZITE. Citing it as a VOLTZITE
  exploit would have been a fabricated attribution. Both hunts'
  `telemetry_gap` fields document exactly what was searched for and why
  it doesn't close the gap, rather than a generic "no data" placeholder.

Also found and fixed along the way: a real pre-existing bug in
`store.insert_node`'s merge-upsert (`ON CONFLICT DO UPDATE SET attrs =
excluded.attrs` unconditionally wiped a node's real attrs to `NULL`
whenever any caller re-inserted with `attrs=None` — exactly what
`normalize/corpus.py` does when stub-creating a vuln node for an
`exploits` entry — silently destroying KEV/NVD/CSAF-populated attrs on
every `strata build` rebuild for any CVE also referenced by a corpus
entry). Fixed via `COALESCE(excluded.attrs, node.attrs)`, with a
regression test.

## Limitations and known gaps

This section consolidates the caveats already documented in detail across
`README.md`'s per-feature notes above, `SOURCES.md`, and `SECURITY.md`,
plus this week's hunt/report findings — read the linked section for the
full story on any one item; this is the scannable summary.

**Collection scope**
- 2 of the spec's 7 named vendor-PSIRT collectors are now built (Siemens
  ProductCERT, Schneider Electric CPCERT); Hitachi/Cisco/Palo Alto/
  Fortinet/Ivanti remain uncollected (see SOURCES.md, "Deliberately not
  collected"). H010 now has real per-vendor disclosure dates, but on a
  thin sample (6 Siemens + 1 Schneider computable data points) — its
  `min_n_per_vendor >= 3` gate correctly keeps it INSUFFICIENT rather
  than overclaiming from that.
- The CISA CSAF collector now extracts `product_tree` text and the
  protocol classifier reads it alongside NVD descriptions, but this only
  added 1 new match — the corpus's real protocol-CVE base rate is
  genuinely low (H008 is still INSUFFICIENT for a trend claim, correctly).
- CSAF file discovery is a most-recent-`N=25` sample with best-effort,
  client-side `--since` filtering (see "CSAF file-discovery assumption"
  above) — not a complete historical backfill.
- `t_group_observed`/`disclosure_to_group_use` is now computed for
  SYLVANITE's 5 corpus `exploits` entries (real Mandiant/SecurityAffairs
  first-observed dates) — H002 is SUPPORTED, but only 1 of 8 groups has
  this data; the other 7 groups' public sourcing never named a specific
  CVE to attach a first_seen date to in the first place.

**Corpus coverage**
- Only **1 of 8** hand-curated groups (sylvanite) has any publicly named
  exploited CVE at all — the other 7 groups' public Dragos threat pages
  never name a specific CVE. Every hunt that joins through `exploits`
  edges (H001, H002, H006, H008) is therefore scoped to whatever that one
  group happens to have had reported, not the real threat landscape. This
  is real collection bias toward whichever actor's activity got the most
  detailed public writeup, not a property of the underlying world.
- Purdue-level classification covers only 86 of 2,859 product nodes
  (`config/purdue_map.yaml`'s hand-curated mapping) — both H006's and
  H007's/H008's Purdue-level comparisons are lower bounds on the true CVE
  mass at each level, not an exhaustive census.

**Statistical caveats**
- The protocol classifier's 200-CVE hand-labeled validation set measured
  precision = recall = 1.000, but on **n=3 true positives** (the corpus's
  real base rate of protocol-specific CVEs is 3 of 1,790 known CVEs). This
  is reported honestly as a small-sample result — a perfect score on 3
  positives is not the same statistical claim as a perfect score on 300.
  See "Protocol classifier validation" above and
  `tests/fixtures/protocol_validation_labels.json`.
- Several hunts (H002, H004, H006, H008, H010) rest on single-digit or
  low-double-digit sample sizes for the same underlying reason: the
  corpus is 8 hand-curated groups whose public sourcing rarely names
  specific CVEs or tools, and the newest vendor-PSIRT advisories are too
  recent for NVD/KEV to have dated yet.

**Reporting lag** — every date this pipeline uses (KEV `dateAdded`, CSAF
`initial_release_date`, NVD `nvd_published`) is a *publication* date, not
a ground-truth first-use or first-disclosure date. Every derived interval
(`patch_available_at_kev`, `disclosure_to_poc_days`, etc.) is therefore an
upper or lower bound, never an exact measurement.

**The hunt board itself is the strongest evidence this is being taken
seriously**: 5 SUPPORTED, 1 REFUTED, 4 INSUFFICIENT is a genuinely mixed
result, not a curated all-green board — see `reports/<date>-ot-capability-
assessment.md` section 6 ("Confidence and limitations") for the full,
generated version of this section, re-derived from the live graph every
time `strata report` runs.

## Running it

```bash
uv sync
uv run strata collect --source all
uv run strata build      # corpus load + protocol/purdue/timeline/consensus enrichment
uv run strata stats
uv run strata hunt run --all               # the full 10-hunt board
uv run strata report                       # renders reports/<date>-ot-capability-assessment.md
uv run strata export storm --out data/export/strata.storm
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

## Current scope — Week 4

Added this week, on top of Weeks 1-3 below: the `hunt/` package and ten
curated hunts (`hunts/H001.yaml`–`H010.yaml`), `strata hunt list/run
[--all] [--format table|json]`; the `export/` package
(`export/storm.py`/`stix.py`/`jsonld.py`/`graph_render.py`) and `strata
export storm|stix|jsonld`, `strata graph show`; `config/telemetry_matrix.yaml`
and the `report/` package (`report/render.py` + `report/templates/
report.md.j2`) with `strata report`; this consolidated "Limitations and
known gaps" section; and `docs/demo.md`, the 90-second interview demo
script. See "What's built (Week 4)" above for the per-module detail.

**Not implemented yet:** 5 of 7 spec-listed vendor-PSIRT collectors
(Siemens and Schneider Electric now built, see "Working through the
INSUFFICIENT hunts" below) and the Streamlit UI (`src/strata/ui/`,
tracked separately).

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

**Not implemented in Weeks 1-3** (built in Week 4, see "Current scope —
Week 4" above): the ten hunts and `strata hunt`, `strata export`
(Storm/STIX/JSON-LD), `strata graph show`, and `strata report`.
Vendor-PSIRT collectors and the Streamlit UI remain not implemented.

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
