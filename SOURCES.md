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

## Deliberately not collected this week

NVD, MITRE ATT&CK, FIRST EPSS, Exploit-DB, PoC-in-GitHub, Nuclei
templates, Metasploit modules, and vendor PSIRT feeds (Siemens,
Schneider, Hitachi, Cisco, Palo Alto, Fortinet, Ivanti) are all in scope
per the engineering spec but are Week 2+ work. `net.py`'s rate limiter is
keyed by hostname and configured via `config/sources.toml` specifically
so these can be added later without reworking the fetch/cache layer.

