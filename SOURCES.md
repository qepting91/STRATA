# Data sources

Every feed STRATA collects, its licensing/terms, cadence, and what it
provides. All sources below are free and require no authentication.

## `cisa-kev` — CISA Known Exploited Vulnerabilities catalog

- **URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **License / terms:** U.S. Government public-domain work product,
  published by CISA (Cybersecurity and Infrastructure Security Agency).
  No authentication, no rate-limit key, no usage agreement required.
- **Cadence:** Updated by CISA on an ad-hoc/daily basis as new entries are
  added to the catalog.
- **What it gives you:** `cveID`, `vendorProject`, `product`,
  `vulnerabilityName`, `dateAdded` (the date CISA confirmed active
  exploitation and added the entry — a policy artifact, not a detection
  timestamp), `knownRansomwareCampaignUse`, `requiredAction`, `dueDate`.
- **Provenance granularity:** one shared `source` row per fetch (the KEV
  catalog is a single JSON payload covering the whole catalog).

## `cisa-csaf` — CISA CSAF advisories (ICS, IT, and vulnerability advisories)

- **URL (discovery):** `https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1`
- **URL (content):** `https://raw.githubusercontent.com/cisagov/CSAF/develop/<path>`
- **License / terms:** U.S. Government public-domain work product,
  published by CISA via the `cisagov/CSAF` GitHub repository. No
  authentication required. Note: the repository's default branch is
  `develop`, not `main` — verified live against the GitHub API; the
  original Week 1 assumption of `main` was a documentation
  simplification, corrected here.
- **Cadence:** CISA publishes new CSAF 2.0 JSON advisories to this
  repository on a rolling basis (multiple per week across ICS, IT, and
  general vulnerability categories).
- **What it gives you:** CSAF 2.0 documents with `document.tracking.id`
  (the advisory ID, e.g. `ICSA-26-006-01`), `document.tracking
  .initial_release_date`, `document.title`, a `product_tree`, and a
  `vulnerabilities[]` array with per-CVE CVSS scores, CWE IDs, and
  remediation guidance.
- **Provenance granularity:** one `source` row per advisory file fetched.
- **Known Week 1 limitation:** there is no "give me the latest N
  advisories" API on this repository. STRATA enumerates the full
  repository tree, filters to the current calendar year's advisory JSON
  files (`csaf_files/{IT,OT,VA}/white/<year>/*.json`), sorts by the
  year/day-of-year/sequence encoded in the filename, and takes the most
  recent `N=25` (a constant in `collect/cisa_csaf.py`). `--since`
  filtering is applied client-side, only within that N-file sample —
  it is best-effort and cannot reach further back in time than whatever
  the sample happens to cover. A more complete backfill (paging further
  into the tree, or using CISA's ROLIE index) is later-week scope.

## `nvd` — NVD CVE enrichment (Week 2, full backfill run Week 3)

- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>`
- **License / terms:** U.S. Government public-domain work product. An
  optional `NVD_API_KEY` unlocks a faster documented tier (50 req/30s vs.
  5 req/30s keyless), sent as the `apiKey` request header via
  `NetClient.fetch()`'s `extra_headers` param (never persisted in the
  cache manifest or the `source` table's URL column).
- **Rate-limit override (Week 3):** `net.py`'s rate limiter is
  static/file-configured and has no concept of "faster when a secret is
  present," so `cli.py` passes a `rate_limit_overrides` dict to
  `NetClient` when `settings.nvd_api_key` is set, raising the effective
  limit for `services.nvd.nist.gov` to 50/30s for that run only. This is
  what turned the full ~1,790-CVE backfill from an estimated ~3 hours
  (Week 2, keyless-tier estimate) into an actually-completed ~15-minute
  run (Week 3, keyed).
- **429 retry (discovered live, Week 3):** even with a valid key and the
  override applied, the very first live request in the full backfill run
  hit an HTTP 429 -- NVD enforces a tighter short-burst limit than its
  documented rolling 50/30s budget. `net.py` now retries a 429 with
  bounded exponential backoff (3 retries, honoring `Retry-After` when
  present), without which the real backfill could not complete at all.
- **Scope decision:** enriches CVEs already present as `vuln` nodes
  (seeded by KEV/CSAF) rather than backfilling the whole NVD corpus --
  one HTTP request per known CVE. `--since` is not meaningful for this
  mode and is ignored with a log notice rather than erroring.
- **What it gives you:** CVSS v3.1 base score/vector, CWE id(s), CPE
  `configurations` matches (-> `product`/`vendor` nodes and
  `affects`/`made_by` edges via `normalize/cpe.py`), and (Week 3) the
  English-language CVE description text, which the protocol classifier
  reads.
- **Provenance granularity:** one `source` row per CVE queried
  (`nvd-<CVE>`).

## `attack` — MITRE ATT&CK enterprise + ICS techniques (Week 2)

- **URL:** `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{enterprise-attack,ics-attack}/{enterprise,ics}-attack.json`
- **License / terms:** MITRE ATT&CK content, Apache 2.0 licensed.
- **Deviation from the build plan:** the plan anticipated needing to
  query the GitHub API for a "latest versioned filename" (the repo also
  keeps per-release copies under subdirectories). Verified live that the
  unversioned `master`-ref path above resolves directly to the current
  bundle for both matrices, so no extra API call is needed.
- **What it gives you:** `technique` nodes (id = ATT&CK id like `T1190`,
  attrs = name/matrix/tactics). No edges -- group-to-technique
  relationships come from the corpus loader, not from ATT&CK content.
- **Provenance granularity:** one `source` row per matrix (enterprise,
  ics).

## `epss` — FIRST.org EPSS scores (Week 2)

- **URL:** `https://api.first.org/data/v1/epss?cve=<comma-separated CVEs>`
- **Host correction:** the engineering spec's illustrative
  `epss.cyentia.com` host is stale/inaccurate. The real, current EPSS API
  is `api.first.org/data/v1/epss`, verified live; it supports batching
  many CVEs into one request (chunked at 100 CVEs/request here to stay
  within the API's own page size).
- **Scope decision:** current-date scores only, filtered to CVEs already
  present as `vuln` nodes -- not a historical daily backfill (deferred).
- **What it gives you:** `epss` and `epss_percentile`
  `metric_observation` rows per CVE. `model_version` is left `None`: the
  live API response does not carry a model-generation field to record
  honestly (a documented Week 2 gap).
- **Provenance granularity:** one shared `source` row per fetch date.

## Signal collectors (Week 2) — `poc-github`, `exploitdb`, `nuclei`, `metasploit`

These write into a separate `signal` table (raw "this CVE was referenced
here, on this date" facts), not the node/edge graph -- see
`strata-engineering-spec.md` §6.1 for why (Week 3's weaponization
timeline reads this table).

- **`poc-github`** (nomi-sec/PoC-in-GitHub): actual layout discovered
  live differs from the plan -- one JSON file **per CVE**
  (`<year>/CVE-XXXX-XXXXX.json`), not one big per-year file. Bounded to a
  sample of `SAMPLE_SIZE=50` CVE files from the current year's directory
  listing (`api.github.com/repos/nomi-sec/PoC-in-GitHub/contents/<year>`)
  to keep a run tractable.
- **`exploitdb`**: `files_exploits.csv` fetched from GitLab
  (`gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`)
  -- Exploit-DB's canonical repo moved off GitHub some years ago. CVEs
  are extracted from the semicolon-separated `codes` column.
- **`nuclei`** (projectdiscovery/nuclei-templates): CVE-named templates
  under `http/cves/<year>/CVE-XXXX-XXXXX.yaml`, enumerated via the GitHub
  Trees API, bounded to `SAMPLE_SIZE=40` most-recent-by-year files. One
  extra `commits?path=...` API call per sampled file gets an honest
  first-commit date (not a "first observed in this run" proxy).
- **`metasploit`** (rapid7/metasploit-framework): no CVE-named-file
  shortcut exists, so this collector enumerates `modules/exploits/**/*.rb`
  via the Trees API, samples `SAMPLE_SIZE=60` files, fetches each one's
  raw source, and regex-matches the `['CVE', '<year>-<num>']` reference
  literal actually used in Metasploit module source. A commit-date lookup
  runs only for files that matched a CVE (bounded by however many that
  turns out to be, not by SAMPLE_SIZE).

**Discovered live rate-limit gap (all four GitHub-hosted signal
collectors, plus `attack`/`nvd` incidentally):** GitHub's REST API
enforces an unauthenticated budget of 60 requests/hour on `api.github.com`
(separate from and stricter than the 1 req/sec spacing rule in
`config/sources.toml`, which has no rolling-window budget concept). The
`nuclei`/`metasploit` collectors' per-file commit-date lookups can exhaust
this budget within a single run if several `api.github.com`-heavy
collectors are run back-to-back inside the same hour. Both collectors
catch the resulting HTTP 403 per file and fall back to a
collection-time proxy date (flagged in the signal's `meta` JSON as
`observed_at_is_collection_time_proxy: true`) rather than aborting the
whole run. This was hit live during Week 2 development. A future pass
could add a real rolling-window budget to the rate limiter and/or send an
authenticated `GITHUB_TOKEN` to raise the cap to 5,000/hour.

## `siemens-psirt` — Siemens ProductCERT CSAF advisories

- **URL:** provider metadata `https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json`
  → ROLIE feed `https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json`
  (both verified live via WebFetch before implementation, not guessed).
- **License / terms:** Siemens's own public TLP:WHITE security advisories,
  published as real CSAF 2.0 documents. No authentication required.
- **What it gives you:** per-advisory `initial_release_date` — the first
  real, per-vendor disclosure date in this graph (KEV/NVD/CISA-CSAF dates
  are all US-government-aggregated, not vendor-native). Feeds H010
  (vendor patch latency).
- **Scope:** bounded to the most recent `N=30` advisories per run
  (`collect/vendor_csaf.py`'s `N_ADVISORIES`), same tractability rationale
  as CISA CSAF's own `N=25`.

## `schneider-psirt` — Schneider Electric CPCERT CSAF advisories

- **URL:** provider metadata `https://www.se.com/.well-known/csaf/provider-metadata.json`
  → `changes.csv`-indexed distribution under `https://www.se.com/.well-known/csaf/`
  (verified live; this is a real, standard CSAF distribution mechanism —
  a plain CSV of `path,timestamp` rows — not a ROLIE feed like Siemens's,
  confirmed by actually fetching it rather than assuming both vendors
  use the same discovery shape).
- **License / terms / what it gives you / scope:** same as Siemens above.

**Real, honest result (live collection, this session):** only 6 of 30
fetched Siemens advisories and 1 of 30 fetched Schneider advisories had a
CVE with an NVD/KEV date already published (most fetched advisories are
for very recent 2026 CVEs NVD/KEV haven't caught up on yet) — i.e. a
computable patch-latency data point. H010's `min_n_per_vendor >= 3` gate
(in `hunt/methods.py`) correctly keeps the hunt INSUFFICIENT on this thin
a sample rather than reporting a comparison built on a single Schneider
data point.

## Deliberately not collected

5 of the spec's 7 named vendor PSIRT feeds (Hitachi, Cisco, Palo Alto,
Fortinet, Ivanti) remain uncollected. `net.py`'s rate limiter is keyed by
hostname and configured via `config/sources.toml` specifically so these
can be added later without reworking the fetch/cache layer — exactly as
Siemens and Schneider were.

## Known corpus gap (Week 2)

`corpus/groups/kamacite.yaml` references `electrum` via `hands_off_to`
(per Dragos's public KAMACITE post: KAMACITE "facilitated intrusion and
transition of operations to ELECTRUM" during the 2015/2016 Ukraine grid
events). ELECTRUM does not have its own corpus YAML file authored yet in
this batch, so `strata corpus load` stub-creates a bare `group` node (id
+ label only) for it so the citing edge is valid without inventing an
uncited full profile — confirmed live: `strata corpus load` reports
"Groups stub-created (1): electrum". Run `strata stats` after a corpus
load to see stub vs. fully-loaded groups reported explicitly.

Citations, aliases, and specific CVE/tool claims for SYLVANITE, VOLTZITE,
and KAMACITE were verified via live web research (not copied from the
engineering spec's illustrative worked example) — see the header comment
in `corpus/citations.yaml` for the six sources used and what each
supports.

