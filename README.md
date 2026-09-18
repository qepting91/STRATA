# STRATA — OT/ICS Threat-Capability Tracking Pipeline

STRATA is a local-only, zero-cost pipeline and read-only dashboard that
correlates public OT/ICS vulnerability data with named, publicly-tracked
threat-group behavior in a single provenance-tracked graph. Every fact
anywhere in the app — every CVE, every tool, every ATT&CK technique,
every claim about a threat group — traces back to a real,
individually-cited public source, shown inline. Nothing is fabricated,
and where the real data genuinely doesn't support a claim, it's stated
as a documented gap instead of hidden.

Run entirely on your own machine against free, public data — no paid
threat-intel feeds, no API keys required (an optional NVD key just speeds
up collection), no malware samples ever downloaded or executed, no
outbound scanning of any kind. See `strata-engineering-spec.md` for the
full architecture and design rationale, and `docs/demo.md` for a
90-second walkthrough.

## Getting started

### Requirements

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** —
  the only package/dependency manager this project uses (no `pip`/
  `venv`/`poetry` workflow is maintained alongside it).
- **git**, to clone the repo.
- A few hundred MB of free disk space for the local SQLite graph and
  cached raw HTTP responses (`data/`, gitignored).
- No paid accounts, API keys, or credentials are required to run
  anything. Optional:
  - A free **[NVD API key](https://nvd.nist.gov/developers/request-an-api-key)**
    — unlocks NVD's faster documented rate-limit tier (50 req/30s vs. 5
    req/30s keyless), turning the full CVE-enrichment backfill from
    roughly 3 hours into roughly 15 minutes. Everything works correctly
    without one, just slower.
  - The **Graphviz `dot` binary** on `PATH` — only used to render a PNG
    of the handoff-model graph export; the plain-text `.dot` export
    works without it either way.
- Platform: developed and tested on Windows; the whole stack is pure
  Python + SQLite with no OS-specific code, so macOS/Linux should work
  the same way (untested by this project's own CI, since there is none
  yet — see "Deliberately excluded" below for what's out of scope).

### Setup

```bash
git clone <this-repo-url>
cd Dragos_test
uv sync                # installs all dependencies into a local .venv
cp .env.example .env   # optional: add NVD_API_KEY= if you have one
```

### First run — collect real, live public data and explore it

```bash
uv run strata collect --source all   # real network calls: KEV, CSAF, NVD, ATT&CK, EPSS, signal feeds
uv run strata build                  # corpus load + protocol/Purdue/timeline/consensus enrichment
uv run strata ui                     # launches the read-only dashboard at http://127.0.0.1:8501
```

The first `collect --source all` run is the slow one (live HTTP calls,
rate-limited per host, ~15–30 minutes depending on whether you supplied
an NVD key). Everything after that reads from the local SQLite graph, and
`strata collect --source all --offline` re-runs the whole pipeline from
the on-disk cache with **zero network calls** — useful for iterating on
enrichment/UI changes without re-fetching anything.

### Running the test suite

```bash
uv run pytest -v
uv run ruff check .
```

Everything above is also summarized in "Running it" further down, and in
`docs/demo.md` as a scripted 90-second walkthrough.

## What it does

1. **Collects** real public OT/ICS-relevant data — vulnerability
   advisories (CISA KEV/CSAF, NVD), exploitation-weaponization signals
   (PoC-in-GitHub, Exploit-DB, Nuclei, Metasploit), vulnerability-scoring
   data (FIRST.org EPSS), vendor-native disclosure dates (Siemens,
   Schneider Electric), and MITRE ATT&CK's own technique/software
   reference data — into a local SQLite graph where **every edge must
   cite a real source row, enforced at the schema level** (a missing
   citation is a hard `IntegrityError`, not a lint warning).
2. **Correlates** that data against a hand-curated, individually-cited
   corpus of all **26 publicly Dragos-tracked ICS threat groups**
   (SYLVANITE, VOLTZITE, XENOTIME, CHERNOVITE, and 22 more) — their real
   targeted sectors/geographies, cited tools/malware, ATT&CK techniques,
   named aliases across other firms' naming conventions, and documented
   access hand-offs between groups.
3. **Enriches** the graph: an ICS-protocol classifier (Modbus/S7comm/
   DNP3/EtherNet-IP/etc., with its own measured precision/recall on a
   hand-labeled validation set), Purdue Enterprise Reference Architecture
   level mapping, a weaponization timeline (disclosure → PoC →
   KEV-listing intervals), adversary-consensus scoring, and a real MITRE
   ATT&CK technique/software cross-reference.
4. **Shows it all** in a read-only Streamlit dashboard (`strata ui`) and
   exports the graph (Synapse Storm, STIX 2.1, JSON-LD) for use in other
   tooling.

## What it shows — the dashboard

`strata ui` launches a local, read-only Streamlit app (every page connects
via a `mode=ro` SQLite URI — it is architecturally incapable of writing to
the database):

- **Search** — keyword search plus dynamic filtering (node type, Purdue
  level, ICS Kill Chain stage, known ransomware use) across every real
  node in the graph, with drill-down into any result's real outgoing/
  incoming edges and their source citations.
- **Threat Groups** — pick any of the 26 tracked groups; see its real
  targeted sectors/geographies, exploited CVEs, tools, ATT&CK techniques,
  and access hand-offs to/from other groups — each claim citing its real
  source inline, and each ATT&CK technique/tool linking out to its real
  MITRE ATT&CK page where one exists (see "What's linked" below).
- **Weaponization Timeline** — disclosure-to-PoC, PoC-to-KEV, and
  patch-before-KEV-listing interval metrics, computed from real dates.
- **Protocol CVEs** — CVEs whose NVD description or CISA CSAF
  product-tree text names a specific ICS-native protocol, plus the
  classifier's own measured precision/recall on a 200-CVE validation set.
- **Visibility Gaps** — a telemetry-requirement matrix (hunt technique →
  telemetry needed → typical OT collection status → difficulty), sorted
  cheapest-to-close-first.
- **Collection Health** — per-source row counts and last-fetch times,
  plus known, honestly-stated gaps.
- **Analytical Frameworks** — the ICS Cyber Kill Chain (Assante & Lee),
  Purdue Enterprise Reference Architecture level, and Pyramid of Pain
  (David Bianco) frameworks applied directly to this project's own real
  data — including an honest accounting of which pyramid layers this
  project has real strength in (Tools, TTPs) versus none at all
  (indicator-level IOCs — deliberately, since STRATA never handles
  malware samples).
- **Threat Hunt Template / Examples** — a reusable, hypothesis-driven OT
  threat-hunting worksheet (hypothesis → intelligence-stream/Collection
  Management Framework mapping → execution → PROVED/DISPROVED/
  INCONCLUSIVE evaluation), plus real worked examples against this
  graph's own AZURITE/VOLTZITE/PYROXENE data. See "A note on the removed
  hunt board" below for why this is a worksheet/reference rather than an
  automated verdict engine.

## Data sources — what's linked

Every fact traces to one of these. Full licensing/cadence/scope-decision
detail for each lives in `SOURCES.md`; the app's own landing page has the
same summary, framed around what each source feeds into.

| Source | Real data collected | Feeds into |
|---|---|---|
| **CISA KEV** | Known-exploited CVE catalog: CVE id, vendor/product, date added, ransomware-use flag | Seeds every `vuln` node; the KEV-listing date anchors every weaponization-timeline interval; the ransomware flag is cross-referenceable against protocol-involvement edges |
| **CISA CSAF** | ICS/IT/vulnerability advisories: tracking id, initial release date, product tree, per-CVE CVSS/CWE | `advisory`/`vuln` nodes; product-tree text is one of the Protocol CVEs classifier's two real inputs |
| **NVD** | CVSS v3.1, CWE, CPE → product/vendor, English CVE description | Purdue-level mapping (via CPE); the classifier's primary input text |
| **MITRE ATT&CK** | Every real enterprise + ICS technique (id/name/description) and software/malware entry, from MITRE's own published STIX data | The real technique name/description/link and tool→software cross-reference shown on Threat Groups |
| **FIRST.org EPSS** | Exploit-prediction score + percentile per CVE | `metric_observation` rows (collected, not yet in a dedicated page — an honest, documented gap) |
| **PoC-in-GitHub / Exploit-DB / Nuclei / Metasploit** | A bounded, real sample of "this CVE was referenced here, on this date" facts | The Weaponization Timeline's disclosure-to-PoC / PoC-to-KEV intervals |
| **Siemens ProductCERT / Schneider Electric CPCERT** | Each vendor's own CSAF advisories — real, vendor-native disclosure dates | The only real per-vendor patch-latency data in this graph (currently thin — see Collection Health) |
| **Corpus** (hand-authored, not fetched) | Every fact for all 26 Dragos-tracked groups, cited individually to `dragos.com/threat/<group>` (plus vendor/press reporting for specific CVE-exploitation claims) | The entire Threat Groups page, the Analytical Frameworks page's ICS Kill Chain stage badges and Pyramid of Pain mapping, and the Threat Hunt Template/Examples pages |

**What's linked (real, external, clickable references you'll actually
see while using it):**
- Every one of the 26 tracked groups' own real `dragos.com/threat/<group>`
  page, shown as an inline citation on its profile.
- Every ATT&CK technique/software a group is cited using links to its
  real `attack.mitre.org/techniques/<id>` or `/software/<id>` page —
  never guessed, only linked where an exact, non-deprecated match exists
  in MITRE's own published data.
- Every CVE's own NVD API URL and, where applicable, its CISA CSAF
  advisory URL, shown as the citation for its `involves`/`affects` edges.

## Why this exists — "RSS is dead"

CISA retired its ICS advisory and KEV RSS/XML feeds in May 2025 with no
replacement. Any pipeline still pointed at
`us-cert.cisa.gov/ics/advisories/advisories.xml` is reading a dead feed.
The machine-readable path today is the CSAF (Common Security Advisory
Framework) JSON corpus published at `github.com/cisagov/CSAF`, plus the KEV
catalog JSON. This is a design decision reflecting where CISA's tooling
actually is now, not a workaround or a limitation.

## What's built — collection & data model

- `net.py` — an egress-allowlisted `httpx` client with per-host rate
  limiting, conditional-request caching (ETag / Last-Modified), on-disk
  snapshotting with SHA-256 provenance, and a strict `--offline` mode that
  makes zero network calls. The rate limiter is source-agnostic (keyed by
  host, configured via `config/sources.toml`), with a per-call override
  mechanism so a supplied `NVD_API_KEY` actually unlocks NVD's faster
  documented tier. It enforces per-request spacing, not a rolling-window
  budget, which does not match GitHub's real unauthenticated
  60-requests/hour REST API cap — the `nuclei`/`metasploit` collectors
  handle this gracefully (see `SOURCES.md`). NVD itself also enforces a
  tighter short-burst limit than its documented 50/30s rolling budget —
  `net.py` retries a `429` with bounded exponential backoff honoring
  `Retry-After`, discovered live while running the full NVD backfill.
- `model/schema.sql` + `model/store.py` — SQLite graph (`source`, `node`,
  `edge`, `metric_observation`, `signal`) with the **non-negotiable
  provenance constraint**: every edge must cite a valid, existing
  `source` row, or the insert raises `sqlite3.IntegrityError`.
- `model/graph_ops.py` — `build_projection`/`descendants_within`: builds
  a NetworkX projection of the graph and does a bounded BFS traversal
  over it, used by `strata graph show` and the Collection Health page's
  rendered handoff-model graph.
- `collect/cisa_kev.py` — CISA Known Exploited Vulnerabilities catalog
  collector.
- `collect/cisa_csaf.py` — CISA CSAF advisory collector, discovering the
  most recent N advisory files via the GitHub Git Trees API (see below).
- `collect/nvd.py` — enriches known `vuln` nodes with CVSS/CWE/CPE data
  from the NVD `cve/2.0` API; `normalize/cpe.py` parses CPE 2.3 strings
  into `product`/`vendor` nodes and `affects`/`made_by` edges.
- `collect/attack.py` — MITRE ATT&CK enterprise + ICS `technique` nodes,
  including each technique's real description and computed MITRE URL.
- `collect/epss.py` — FIRST.org EPSS scores as `metric_observation` rows.
- `collect/poc_github.py`, `collect/exploitdb.py`, `collect/nuclei.py`,
  `collect/metasploit.py` — weaponization-timing signal collectors,
  writing into a dedicated `signal` table (not the node/edge graph).
- `collect/siemens_psirt.py`, `collect/schneider_psirt.py` — vendor CSAF
  collectors for real, vendor-native advisory disclosure dates.
- `normalize/models.py` + `normalize/corpus.py` — pydantic-validated
  corpus loader: `corpus/citations.yaml` + `corpus/groups/*.yaml` (all
  **26** Dragos-tracked groups) -> `group`/`tool`/`vuln`/`technique`/
  `sector`/`geo` nodes and their edges, with fail-loud citation
  validation and stub-node creation for hands-off-to targets that lack
  their own corpus entry.
- `enrich/protocol.py` — rule-based ICS protocol classifier
  (`config/protocols.yaml`: Modbus/S7comm/IEC-104/DNP3/IEC-61850/
  EtherNet-IP/OPC-UA/BACnet/MQTT) over NVD description text and CSAF
  advisory product-tree text, writing `vuln -[:involves]-> protocol`
  edges with an evidence note. **Real, measured precision/recall on a
  200-CVE hand-labeled validation set: precision = 1.000 (3/3), recall =
  1.000 (3/3)** — see "Protocol classifier validation" below for the
  methodology and an honest caveat about what a sample this small can
  and can't tell you.
- `enrich/purdue.py` — maps `product` nodes to a Purdue level/class via
  `config/purdue_map.yaml`, merged into the product's `attrs`.
- `enrich/timeline.py` — the weaponization timeline: `t_disclosed`
  (earliest of vendor CSAF/NVD/KEV dates), PoC-corroboration-tiered
  `t_first_poc`, derived intervals (`disclosure_to_poc_days`,
  `poc_to_kev_days`, `detection_lag_days`, `patch_available_at_kev`,
  `disclosure_to_group_use`) as `metric_observation` rows.
- `enrich/consensus.py` — adversary-consensus scoring: for each product,
  the count of distinct groups whose `exploits` edges reach a CVE that
  `affects` it (a 2-hop SQL join, not a graph library — a 4-edge join
  doesn't need one).
- `enrich/attack_software.py` — cross-references every corpus tool's
  exact name/alias against MITRE's own published ATT&CK software/malware
  data, merging a real `attack_software_id`/`attack_software_url` onto
  matching tool nodes (never a fuzzy/guessed match).
- `cli.py` — `strata collect --source {kev,csaf,nvd,attack,epss,
  poc-github,exploitdb,nuclei,metasploit,siemens-psirt,schneider-psirt,
  all}`, `strata stats`, `strata corpus load`, `strata build` (corpus
  load + all enrichment passes in one command), `strata export
  {storm,stix,jsonld}`, `strata graph show --group <id> --depth N`, and
  `strata ui`.

## CSAF file-discovery assumption (read this before relying on it)

`github.com/cisagov/CSAF` has no stable "latest N advisories" API endpoint.
This collector enumerates the whole repository tree via
`GET api.github.com/repos/cisagov/CSAF/git/trees/main?recursive=1`, filters
blob paths down to the current calendar year's advisory JSON files, sorts
them, and takes the most recent `N=25` (a constant in `cisa_csaf.py`) by
fetching each one's raw content from `raw.githubusercontent.com`. `--since`
filtering on CSAF is therefore **best-effort and client-side**, applied
only to the N-file sample already fetched — it cannot reach further back
than that sample. A more thorough backfill (e.g. paging further back or
using the ROLIE feed index) remains a documented future improvement.

## Protocol classifier validation

The corpus's actual base rate of ICS-protocol-specific CVEs turned out to
be very low: **only 3 of 1,790 known CVEs** (KEV/CSAF/NVD-sourced,
overwhelmingly enterprise edge-device CVEs like Ivanti/Fortinet/Cisco
appliances) trigger any protocol keyword match at all. The 200-CVE
validation sample is therefore **stratified, not random**: all 3
keyword-matching CVEs plus 197 randomly sampled non-matching CVEs, so
both precision (checking the matched set) and recall (checking a large
sample of the unmatched set for anything the classifier missed) are
measurable at all. An independent reviewer — explicitly instructed not
to just re-run the same keyword rule, which would be circular — read all
200 descriptions in full. Result: **3/3 true positives, 0 false
positives found in the 197 negatives** → precision = recall = 1.000.
This is reported honestly as a small-sample result, not dressed up as
more statistically confident than it is. See
`tests/fixtures/protocol_validation_labels.json` (`labeling_summary`
field) for the full methodology and the reviewer's caveats, and
`tests/test_enrich_protocol_validation_set.py` for the test that
reproduces these exact numbers against the real classifier.

**Real bugs found and fixed during this validation work** (documented
here rather than quietly folded in, since surfacing your own errors is
this project's whole stated ethos): the classifier originally used plain
substring matching with no word boundaries, so "Mongoose Web Server"
matched the IEC-61850 keyword "goose", and "heapdump" matched the
IEC-104 keyword "apdu" — both fixed with `\b`-anchored regex matching.
Separately, `enrich/protocol.py`'s `run()` only ever *inserted*
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

## What's built — export & analyst frameworks

- `export/` package — `export/storm.py` (a generated, syntax-checked
  Synapse Storm script; paired queries in `docs/storm-queries.md`),
  `export/stix.py` (a STIX 2.1 bundle, `intrusion-set`/`malware`/`tool`/
  `attack-pattern`/`vulnerability`/`relationship`, validated with
  `stix2-validator`), `export/jsonld.py` (a raw JSON-LD graph dump),
  `export/graph_render.py` (a static Graphviz/DOT render of the
  `hands_off_to` handoff model). `strata export {storm,stix,jsonld}
  [--out PATH]`, `strata graph show --group sylvanite --depth 2`.
- `config/telemetry_matrix.yaml` — the telemetry requirement matrix
  (hunt technique → telemetry required → typical OT collection status →
  difficulty), rendered ranked cheapest-to-close-first on the Visibility
  Gaps page.
- `normalize/hunt_hypothesis_models.py` + `normalize/hunt_hypothesis_loader.py`
  + `corpus/hunt_hypotheses/*.yaml` — the Threat Hunt Template/Examples
  pages' data: a hypothesis-driven-hunting worksheet format (hypothesis,
  PIR reference, Collection Management Framework notes stating plainly
  what this graph does/doesn't model, outcome criteria), with real
  worked examples for AZURITE/VOLTZITE/PYROXENE grounded in their actual
  corpus data.
- `docs/demo.md` — a 90-second interview demo script.

## A note on the removed hunt board

An earlier version of this project computed ten falsifiable hunts
(hypothesis + explicit falsification condition, evaluated fresh against
the live graph as SUPPORTED/REFUTED/INSUFFICIENT) and rendered them as a
"Hunt Board" page, plus a generated Markdown intel report built entirely
from those hunt results. Both were removed.

The reasoning: a *true* threat hunt needs first-party telemetry (host/
network logs, EDR, identity/access data) to actually prove or disprove a
hypothesis against a specific environment. This project only ever
aggregates and correlates public, open-source reporting — real,
individually-cited data, but never a defender's own telemetry. Computing
a SUPPORTED/REFUTED/INSUFFICIENT verdict from that and presenting it as
a completed hunt outcome would have been a more subtle version of
exactly the overclaiming this project's whole provenance model exists to
prevent, no matter how carefully each individual verdict's `insufficient_if`
threshold was tuned. The real, still-standing value — the provenance-
tracked correlation graph, the real external citations, and a reusable
hypothesis-driven hunting *worksheet* for when you do have first-party
data (see "Threat Hunt Template / Examples" above) — is what remains.

`model/graph_ops.py`'s `build_projection`/`descendants_within` (the
traversal logic the old H009 handoff hunt used) survived the removal
unchanged, since a bounded capability traversal (`strata graph show`,
and the Collection Health page's rendered handoff graph) is a factual
"what does the graph say is reachable" query, not a hunt verdict.

## Limitations and known gaps

This section consolidates the caveats already documented in detail across
`README.md`'s per-feature notes above, `SOURCES.md`, and `SECURITY.md` —
read the linked section for the full story on any one item; this is the
scannable summary.

**Collection scope**
- 2 of 7 named vendor-PSIRT collectors are built (Siemens ProductCERT,
  Schneider Electric CPCERT); Hitachi/Cisco/Palo Alto/Fortinet/Ivanti
  remain uncollected (see `SOURCES.md`, "Deliberately not collected").
  The real per-vendor disclosure-date sample from the 2 built collectors
  is thin (6 Siemens + 1 Schneider computable data points) — too few to
  support a trustworthy cross-vendor patch-latency comparison.
- The CISA CSAF collector extracts `product_tree` text and the protocol
  classifier reads it alongside NVD descriptions, but this only added 1
  new match — the corpus's real protocol-CVE base rate is genuinely low.
- CSAF file discovery is a most-recent-`N=25` sample with best-effort,
  client-side `--since` filtering (see "CSAF file-discovery assumption"
  above) — not a complete historical backfill.
- `disclosure_to_group_use` is computed for SYLVANITE's 5 corpus
  `exploits` entries (real Mandiant/SecurityAffairs first-observed
  dates, median **-38 days** — real zero-day exploitation predating
  public disclosure, not a data error), but only 1 of the corpus's 26
  tracked groups has this data; the other 25 groups' public sourcing
  never named a specific CVE to attach a first_seen date to in the first
  place.

**Corpus coverage**
- The corpus covers all **26** Dragos-tracked ICS threat groups. Only
  **1 of 26** (sylvanite) has any publicly named exploited CVE at all —
  the other 25 groups' public Dragos threat pages never name a specific
  CVE. This is real collection bias toward whichever actor's activity
  got the most detailed public writeup, not a property of the underlying
  world.
- Purdue-level classification covers only 86 of 2,859 product nodes
  (`config/purdue_map.yaml`'s hand-curated mapping) — the Analytical
  Frameworks page's Purdue-level CVE-mass chart is a lower bound on the
  true CVE mass at each level, not an exhaustive census.

**Statistical caveats**
- The protocol classifier's 200-CVE hand-labeled validation set measured
  precision = recall = 1.000, but on **n=3 true positives** (the corpus's
  real base rate of protocol-specific CVEs is 3 of 1,790 known CVEs). This
  is reported honestly as a small-sample result — a perfect score on 3
  positives is not the same statistical claim as a perfect score on 300.
  See "Protocol classifier validation" above and
  `tests/fixtures/protocol_validation_labels.json`.

**Reporting lag** — every date this pipeline uses (KEV `dateAdded`, CSAF
`initial_release_date`, NVD `nvd_published`) is a *publication* date, not
a ground-truth first-use or first-disclosure date. Every derived interval
(`patch_available_at_kev`, `disclosure_to_poc_days`, etc.) is therefore an
upper or lower bound, never an exact measurement.

**On the removed hunt board** — see "A note on the removed hunt board"
above for why this project no longer presents computed SUPPORTED/
REFUTED/INSUFFICIENT verdicts as completed threat hunts.

## Running it

```bash
uv sync
uv run strata collect --source all
uv run strata build      # corpus load + protocol/purdue/timeline/consensus enrichment
uv run strata stats
uv run strata export storm --out data/export/strata.storm
uv run strata ui         # launches the read-only Streamlit dashboard
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

## Deliberately excluded

Shodan, Censys, VirusTotal (beyond metadata-only free tier), Recorded
Future, Joe Sandbox. All either paid, rate-crippled, or require handling
executable samples, which this project never does. See
`strata-engineering-spec.md` §4.2.

## Legal / ethical framing

This repository reproduces no proprietary threat-intelligence report
content. Threat group names are public nomenclature with attribution to
the naming organization (overwhelmingly Dragos's own public
`dragos.com/threat/<group>` pages). No active scanning of any kind is
performed, ever — only HTTPS GETs to a static allowlist of public feed
hosts. No malware samples are downloaded, stored, or executed.

See `SECURITY.md` for the egress-allowlist model and secrets handling, and
`SOURCES.md` for per-source licensing/terms and cadence.
