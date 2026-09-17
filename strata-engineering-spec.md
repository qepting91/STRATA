# STRATA — Engineering Specification v1.0

**OT Threat Group Capability Tracking Pipeline**

A local-only, zero-cost collection and analysis pipeline that builds a provenance-tracked graph of OT/ICS adversary capabilities from public data, and runs falsifiable hunt hypotheses against it.

Built as a portfolio artifact for the Dragos Senior Capabilities Hunter role. Everything runs on a laptop with no paid services, no cloud, and no malware handling.

---

## 1. Design constraints

| Constraint | Implementation |
|---|---|
| Free | Only public feeds. One optional free API key (NVD). No Shodan, Censys, VT premium, Recorded Future. |
| Local | SQLite + filesystem. No server processes, no inbound ports, no hosted DB. |
| Secure | Outbound HTTPS only, to a static allowlist. No code execution on collected data. No binaries handled. |
| Reproducible | Every fetch snapshotted with SHA-256 + timestamp. `--offline` replays from cache. |
| Auditable | Every graph edge carries a source ID resolving to a public URL. No unsourced assertions. |
| Defensible | No reproduction of Dragos WorldView content. Group names used as public nomenclature only. |

### 1.1 Explicit non-goals

- Does not run Synapse. It produces Synapse-ready output (§7.3) to demonstrate modeling fluency without the infrastructure.
- Does not handle malware samples. No detonation, no unpacking, no binary I/O.
- Does not scan the internet. No active reconnaissance of any kind, ever.
- Does not claim attribution. It models what public reporting asserts, with citation.

---

## 2. Architecture

```
                   ┌──────────────────────────────────────────┐
                   │  collect/   (HTTPS out, allowlist only)  │
                   │  CSAF · KEV · NVD · ATT&CK · EPSS ·      │
                   │  ExploitDB · PoC-in-GitHub · Nuclei ·    │
                   │  Metasploit · Vendor PSIRT CSAF          │
                   └────────────────┬─────────────────────────┘
                                    │ raw snapshots (sha256 + ts)
                                    ▼
                   ┌──────────────────────────────────────────┐
                   │  normalize/  pydantic models, one schema │
                   └────────────────┬─────────────────────────┘
                                    │
       corpus/ (hand-curated ───────┤
       group TTPs, cited)           ▼
                   ┌──────────────────────────────────────────┐
                   │  model/      SQLite graph (nodes+edges)  │
                   │              provenance on every edge    │
                   └────────────────┬─────────────────────────┘
                                    ▼
                   ┌──────────────────────────────────────────┐
                   │  enrich/     weaponization timeline,     │
                   │              protocol tagging, Purdue    │
                   │              level, adversary consensus  │
                   └────────────────┬─────────────────────────┘
                                    ▼
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
   ┌────────────┐           ┌──────────────┐          ┌──────────────┐
   │  hunt/     │           │  report/     │          │  export/     │
   │  10 hunts  │           │  markdown    │          │ Storm · STIX │
   │  verdicts  │           │  intel report│          │ JSON-LD      │
   └────────────┘           └──────────────┘          └──────────────┘
```

---

## 3. Repository layout

```
strata/
├── pyproject.toml              # uv/hatch, hash-pinned
├── uv.lock
├── Makefile                    # make collect | build | hunt | report | test
├── README.md
├── SECURITY.md                 # threat model for the tool itself
├── SOURCES.md                  # every feed, its licence, its terms
├── .env.example                # NVD_API_KEY only
│
├── config/
│   ├── sources.toml            # feed URLs, cadence, rate limits
│   ├── allowlist.txt           # permitted egress hostnames
│   ├── purdue_map.yaml         # product family → Purdue level
│   └── protocols.yaml          # ICS protocol keyword/port/function-code table
│
├── corpus/                     # the human-authored layer; all cited
│   ├── groups/
│   │   ├── sylvanite.yaml
│   │   ├── voltzite.yaml
│   │   ├── kamacite.yaml
│   │   ├── electrum.yaml
│   │   ├── azurite.yaml
│   │   ├── pyroxene.yaml
│   │   ├── bauxite.yaml
│   │   └── parisite.yaml
│   ├── relationships.yaml      # handoff / overlap / attribution edges
│   ├── tools.yaml              # web shells, loaders, C2, wipers
│   ├── citations.yaml          # source registry: id → url, publisher, date
│   └── schema/
│       ├── group.schema.json
│       └── relationship.schema.json
│
├── src/strata/
│   ├── __init__.py
│   ├── cli.py                  # typer
│   ├── settings.py             # pydantic-settings
│   ├── net.py                  # allowlisted session, rate limiter, cache
│   ├── collect/
│   │   ├── base.py             # Collector ABC
│   │   ├── cisa_csaf.py
│   │   ├── cisa_kev.py
│   │   ├── nvd.py
│   │   ├── attack.py
│   │   ├── epss.py
│   │   ├── exploitdb.py
│   │   ├── poc_github.py
│   │   ├── nuclei.py
│   │   ├── metasploit.py
│   │   └── vendor_csaf.py
│   ├── normalize/
│   │   ├── models.py           # pydantic entity models
│   │   ├── cpe.py              # CPE 2.3 parse / vendor-product join
│   │   └── dedupe.py
│   ├── model/
│   │   ├── schema.sql
│   │   ├── store.py            # SQLite DAO
│   │   └── graph.py            # networkx projection
│   ├── enrich/
│   │   ├── timeline.py         # weaponization timeline
│   │   ├── protocol.py         # ICS protocol classifier
│   │   ├── purdue.py           # Purdue level assignment
│   │   └── consensus.py        # adversary consensus scoring
│   ├── hunt/
│   │   ├── runner.py           # loads hunt yaml, executes, renders verdict
│   │   └── verdicts.py
│   ├── report/
│   │   ├── render.py           # jinja2 → markdown
│   │   └── templates/
│   └── export/
│       ├── storm.py            # Synapse Storm ingest generator
│       ├── stix.py             # STIX 2.1 bundle
│       └── jsonld.py
│
├── hunts/
│   ├── H001-edge-convergence.yaml
│   ├── H002-time-to-weaponization.yaml
│   ├── H003-patch-before-exploit.yaml
│   ├── H004-webshell-attribution.yaml
│   ├── H005-ransomware-ics-protocol.yaml
│   ├── H006-cellular-gateway-convergence.yaml
│   ├── H007-purdue-cve-mass.yaml
│   ├── H008-protocol-cve-trend.yaml
│   ├── H009-handoff-traversal.yaml
│   └── H010-vendor-patch-latency.yaml
│
├── tests/
│   ├── fixtures/               # frozen API responses
│   ├── test_collectors.py
│   ├── test_normalize.py
│   ├── test_enrich.py
│   ├── test_hunts.py
│   └── test_export.py
│
├── data/                       # .gitignored
│   ├── raw/<source>/<date>/    # immutable snapshots
│   ├── interim/
│   └── strata.db
│
└── reports/
    └── 2026-XX-ot-capability-assessment.md
```

---

## 4. Data sources

All free. All keyless except NVD (free key, optional).

| ID | Source | Endpoint | Auth | Cadence | Gives you |
|---|---|---|---|---|---|
| `cisa-csaf` | CISA CSAF advisories | `github.com/cisagov/CSAF` (raw JSON) | none | daily | ICS/ICSMA/AA advisories, CSAF 2.0, vendor+product trees, CVSS, remediation |
| `cisa-kev` | KEV catalog | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | none | daily | `dateAdded`, `knownRansomwareCampaignUse`, required action |
| `nvd` | NVD CVE 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | free key | incremental | CVSS, CWE, CPE, published/lastModified |
| `attack` | MITRE ATT&CK STIX | `github.com/mitre-attack/attack-stix-data` | none | on release | Enterprise + ICS technique objects, relationships |
| `epss` | FIRST EPSS | `epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` | none | daily | exploitation probability, percentile |
| `exploitdb` | Exploit-DB | `gitlab.com/exploit-database/exploitdb` `files_exploits.csv` | none | weekly | public exploit publication dates |
| `poc-github` | PoC-in-GitHub | `github.com/nomi-sec/PoC-in-GitHub` (per-year JSON) | none | weekly | CVE → PoC repo `created_at` — **primary weaponization signal** |
| `nuclei` | Nuclei templates | `github.com/projectdiscovery/nuclei-templates` | none | weekly | template commit date per CVE — detection-availability signal |
| `metasploit` | Metasploit modules | `github.com/rapid7/metasploit-framework` | none | weekly | module `DisclosureDate` + file commit date |
| `psirt-siemens` | Siemens ProductCERT | CSAF provider metadata / ROLIE feed | none | weekly | original vendor disclosure + fix dates |
| `psirt-schneider` | Schneider Electric SE | CSAF / advisory index | none | weekly | same |
| `psirt-hitachi` | Hitachi Energy | CSAF / advisory index | none | weekly | same |
| `psirt-cisco` | Cisco PSIRT | CSAF provider metadata | none | weekly | edge/network gear fix dates |
| `psirt-paloalto` | Palo Alto Networks | CSAF / security advisories | none | weekly | GlobalProtect, PAN-OS |
| `psirt-fortinet` | Fortinet PSIRT | advisory index | none | weekly | FortiGate, FortiOS |
| `psirt-ivanti` | Ivanti Security Advisories | advisory index | none | weekly | Connect Secure, EPMM |

### 4.1 Source notes

- **RSS is dead.** CISA retired its advisory and KEV RSS feeds in May 2025 with no replacement. Anyone whose pipeline still points at `us-cert.cisa.gov/ics/advisories/advisories.xml` is running on a dead feed. The CSAF repo is the machine-readable path now. *Say this in the interview — it demonstrates current collection knowledge rather than a tutorial copied from 2023.*
- **NVD rate limit:** 5 req / rolling 30s without a key, 50 / 30s with. `resultsPerPage` max 2000, pagination via `startIndex` mandatory. Date-range queries capped at 120 consecutive days. Backfill once, then sync on `lastModStartDate`.
- **Vendor PSIRT coverage is uneven.** Siemens is the strongest CSAF publisher. Rockwell gates some content behind accounts — do not scrape gated content; record it as a collection gap and report it. That gap is itself a finding.
- **Collect edge vendors, not just ICS vendors.** The hunts that matter (H001, H003, H006) concentrate on Purdue 3.5 gear — Ivanti, Fortinet, Palo Alto, Citrix, F5. Pulling patch dates only from ICS-native PSIRTs would compute `patch_available_at_kev` over a population that excludes most of the CVEs the adversaries actually use. The enterprise PSIRT collectors are load-bearing for those three hunts, not optional breadth.

### 4.2 Deliberately excluded

Shodan, Censys, VirusTotal (beyond metadata-only free tier), Recorded Future, Joe Sandbox. All either paid, rate-crippled, or requiring sample handling. The spec's value does not depend on them. State this explicitly in the README as a design decision, not a limitation.

---

## 5. Data model

Synapse-shaped so the mapping is obvious. Stored in SQLite; projected into NetworkX for traversal.

### 5.1 Node types

| STRATA type | Synapse analogue | Key fields |
|---|---|---|
| `group` | `risk:threat` | name, stage (ICS CKC 1/2), org_attrib, first_seen |
| `alias` | `risk:threat:name` | name, assigning_org |
| `campaign` | `risk:campaign` | name, start, end, group_ref |
| `technique` | `it:mitre:attack:technique` | attack_id, matrix (ics/enterprise), tactic |
| `vuln` | `risk:vuln` | cve, cvss_v31, cwe, published, kev_added, epss |
| `product` | `it:prod:softver` / `hardware` | vendor, name, cpe, purdue_level |
| `vendor` | `ou:org` | name, psirt_url |
| `tool` | `it:prod:soft` | name, class (webshell/loader/c2/wiper/raas), oss_bool |
| `protocol` | custom `ics:proto` | name, default_port, spec |
| `sector` | `ou:industry` | name, naics |
| `geo` | `pol:country` | iso2 |
| `advisory` | `media:news` | id, publisher, url, published |
| `source` | `meta:source` | id, url, publisher, retrieved, sha256 |

### 5.2 Edge types

```
group      -[:uses]->            tool          {first_seen, last_seen, src}
group      -[:exploits]->        vuln          {first_seen, src}
group      -[:targets]->         sector|geo    {src}
group      -[:targets]->         product       {src}
group      -[:implements]->      technique     {src}
group      -[:hands_off_to]->    group         {relationship: iab_to_stage2, src}
group      -[:overlaps_with]->   group         {assigning_org, src}
vuln       -[:affects]->         product       {cpe_match}
vuln       -[:involves]->        protocol      {evidence: keyword|functioncode}
product    -[:made_by]->         vendor
advisory   -[:describes]->       vuln|product
tool       -[:used_by_multiple]  (derived)
```

### 5.3 Provenance rule — non-negotiable

Every edge row requires a non-null `source_id` FK into `source`. The DAO refuses inserts without one. Enforced at the schema level:

```sql
CREATE TABLE edge (
  id          INTEGER PRIMARY KEY,
  src_node    TEXT NOT NULL REFERENCES node(id),
  dst_node    TEXT NOT NULL REFERENCES node(id),
  rel         TEXT NOT NULL,
  first_seen  TEXT,
  last_seen   TEXT,
  confidence  TEXT NOT NULL CHECK (confidence IN ('high','moderate','low')),
  source_id   TEXT NOT NULL REFERENCES source(id),
  note        TEXT,
  UNIQUE(src_node, dst_node, rel, source_id)
);
```

This is the single most interview-relevant design decision in the project. It is what separates an intel graph from an indicator dump, and it is what Synapse's `.seen` and light-edge model exists to enforce.

### 5.4 Mutable metrics are time series, not columns

EPSS scores change daily. CVSS gets rescored. NVD records gain CPEs and CWEs months after publication. Storing any of these as a column on the `vuln` node destroys the analytically interesting value — the score **as it stood on the day the adversary used it**.

Do not solve this with `valid_from` / `valid_until` on every node and edge. Full bitemporal versioning across the whole schema is a large complexity tax to solve a problem confined to a handful of scalar metrics. Separate the mutable scalars into an append-only observation table and leave the graph alone:

```sql
CREATE TABLE metric_observation (
  cve           TEXT NOT NULL,
  metric        TEXT NOT NULL,        -- 'epss', 'epss_percentile', 'cvss_v31_base'
  value         REAL NOT NULL,
  observed_on   TEXT NOT NULL,        -- date the value was published, not fetched
  model_version TEXT,                 -- 'epss_v4', 'cvss_3.1'
  source_id     TEXT NOT NULL REFERENCES source(id),
  PRIMARY KEY (cve, metric, observed_on)
);
```

Point-in-time lookup:

```sql
SELECT value FROM metric_observation
WHERE cve = ? AND metric = 'epss' AND observed_on <= ?
ORDER BY observed_on DESC LIMIT 1;
```

**`model_version` is not decoration.** EPSS has been rescored across model generations, and scores are not comparable across them — a 0.4 under one model generation does not mean what a 0.4 means under another. Any longitudinal EPSS claim that ignores model version is wrong. Record it, and when a hunt compares scores across a window that spans a model change, the runner emits a warning and the report says so. Backfill is straightforward: the EPSS daily CSVs are published per-date and retrievable historically, so the observation table can be populated for the full corpus window in one pass.

### 5.5 Concurrency

The database is initialised WAL-mode at creation:

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
```

Without this, a `strata build` running while the UI is open produces `database is locked`. WAL permits concurrent readers alongside a single writer.

One deployment caveat: a WAL reader still needs to create and write the `-shm` and `-wal` sidecar files, so `mode=ro` works but a genuinely read-only *filesystem* does not. In the §9 container, `/app/data` is a writable volume for exactly this reason — the `read_only: true` root filesystem does not cover it. If you ever need a truly immutable mount, use `mode=ro&immutable=1` and accept that writes are blocked entirely.

### 5.6 Corpus entry format

```yaml
# corpus/groups/sylvanite.yaml
id: sylvanite
name: SYLVANITE
naming_org: Dragos
ics_kill_chain_stage: 1
role: initial_access_broker
aliases:
  - {name: UNC5221, org: Mandiant, src: S-0041}
  - {name: UNC5174, org: Mandiant, src: S-0041}
targets:
  sectors: [electric, water_wastewater, oil_gas, manufacturing, public_admin]
  geos: [US, GB, FR, JP, KR, PH, SA]
  src: S-0012
exploits:
  - {cve: CVE-2023-46805, product: ivanti_connect_secure, src: S-0003}
  - {cve: CVE-2024-21887, product: ivanti_connect_secure, src: S-0003}
  - {cve: CVE-2025-4427,  product: ivanti_epmm,           src: S-0018}
  - {cve: CVE-2025-4428,  product: ivanti_epmm,           src: S-0018}
  - {cve: CVE-2025-31324, product: sap_netweaver,         src: S-0021}
tools:
  - {name: Godzilla,   class: webshell, src: S-0012}
  - {name: KrustyLoader, class: loader, src: S-0012}
  - {name: frp,        class: tunnel,   oss: true, src: S-0012}
techniques:
  - {attack_id: T1190, matrix: enterprise, src: S-0003}
  - {attack_id: T1505.003, matrix: enterprise, src: S-0012}
hands_off_to:
  - {group: voltzite, confidence: moderate, src: S-0012}
```

`citations.yaml` resolves `S-0012` to a public URL, publisher, and retrieval date. **Every source must be a publicly linkable document.** If a claim only exists in a paywalled report, it does not go in the corpus — it goes in the README's "known gaps" section.

---

## 6. Enrichment — the derived datasets

This is the original contribution. Nobody publishes these joined.

### 6.1 Weaponization timeline (`enrich/timeline.py`)

Per CVE, compute and store:

| Field | Source |
|---|---|
| `t_disclosed` | **min**(vendor CSAF `initial_release_date`, NVD `published`, KEV `dateAdded`) |
| `t_nvd_published` | NVD `published` — retained separately |
| `t_vendor_advisory` | vendor CSAF `initial_release_date` |
| `t_cisa_advisory` | CISA CSAF |
| `t_first_poc` | earliest **corroborated** PoC (see below) |
| `t_first_poc_claimed` | earliest uncorroborated PoC repo `created_at` |
| `t_nuclei_template` | first commit touching the template |
| `t_metasploit` | module file first commit |
| `t_kev` | KEV `dateAdded` |
| `t_group_observed` | corpus `first_seen` on `group-[:exploits]->vuln` |

**`t_disclosed` cannot be NVD `published`.** For exactly the fast-moving edge N-days this project cares about, NVD enrichment routinely lags the vendor advisory — sometimes by weeks. Anchoring on NVD would produce negative `disclosure_to_poc_days` values for the most important cases in the dataset, which is both wrong and an obvious tell that nobody checked. Take the minimum across the three, record which source won in `t_disclosed_src`, and report the spread.

#### PoC corroboration

Treating every indexed GitHub repository as a working exploit is the fastest way to a wrong headline number. The index contains placeholder repos, README-only stubs, automated forks, and reposted collections — all with a `created_at` that compresses the metric downward.

Each candidate gets a `poc_confidence` before it counts:

| Confidence | Criteria |
|---|---|
| `high` | Appears in ExploitDB or Metasploit, **or** has a Nuclei template, **or** the repo carries independent signals: >10 stars, >1 commit, and non-trivial file content |
| `moderate` | Repo has >1 commit and a non-README code file, but no external corroboration |
| `low` | Single commit, README-only, or name matches a known auto-generated pattern |

`t_first_poc` uses `high` and `moderate` only. `t_first_poc_claimed` keeps the unfiltered minimum so the two can be reported side by side — the delta between them is itself a finding about OSINT data quality, and worth a paragraph in the report.

Star count is a weak signal used only in combination, never alone: stars accrue after the fact and lag the behaviour being measured.

Derived metrics:

```
disclosure_to_poc_days      = t_first_poc  - t_disclosed
poc_to_kev_days             = t_kev        - t_first_poc
disclosure_to_group_use     = t_group_observed - t_disclosed
patch_available_at_kev      = t_vendor_advisory <= t_kev
detection_lag_days          = t_nuclei_template - t_first_poc
```

`disclosure_to_group_use` per group is the headline number. The public reporting asserts SYLVANITE weaponises N-days almost immediately after PoC release. This pipeline produces a **distribution with a median and an n**, which is a materially stronger claim than the adjective.

Three biases that must be stated wherever this metric appears:

- **Reporting lag.** `t_group_observed` is a publication date, not a first-use date. Every interval is an upper bound of unknown width.
- **Selection bias.** The corpus only contains CVEs that someone published about. Exploitation that was never detected or never written up is invisible, and there is no reason to assume it is distributed like the visible set.
- **KEV `dateAdded` is a policy artefact.** CISA adds entries in batches on its own cadence. It is evidence that exploitation was confirmed by some date, not evidence of when exploitation began. Never use it as a detection timestamp.

### 6.2 ICS protocol classifier (`enrich/protocol.py`)

Rule-based, transparent, testable. `config/protocols.yaml` defines per protocol:

```yaml
- name: Modbus
  ports: [502]
  keywords: [modbus, "function code", "holding register", "coil"]
  function_codes: {3: read_holding, 6: write_single, 16: write_multiple}
- name: S7comm
  ports: [102]
  keywords: [s7comm, "s7-300", "s7-400", "s7-1200", "s7-1500", cotp, tsap]
- name: IEC-104
  ports: [2404]
  keywords: ["iec 60870-5-104", "iec-104", asdu, "apdu"]
- name: DNP3
  ports: [20000]
  keywords: [dnp3, "outstation", "distributed network protocol"]
- name: IEC-61850
  ports: [102, 61850]
  keywords: ["iec 61850", goose, "mms", "sampled values"]
- name: EtherNet/IP
  ports: [44818, 2222]
  keywords: ["ethernet/ip", "cip", "common industrial protocol"]
- name: OPC-UA
  ports: [4840]
  keywords: ["opc ua", "opc-ua"]
- name: BACnet
  ports: [47808]
  keywords: [bacnet]
- name: MQTT
  ports: [1883, 8883]
  keywords: [mqtt]
```

Applied over CVE descriptions + CSAF product trees. Output: `vuln-[:involves]->protocol` edges with `evidence` recording which rule fired. Precision is measurable — hand-label a 200-CVE validation set, report precision/recall in the README. **Publishing your own error rate is a credibility move most portfolio projects skip.**

### 6.3 Purdue level assignment (`enrich/purdue.py`)

Hand-curated mapping in `config/purdue_map.yaml`, joined via CPE vendor/product:

```yaml
levels:
  5: [internet_facing_dmz]
  4: [erp, email, enterprise_ad]
  3.5: [vpn_gateway, firewall, jump_host, remote_access, cellular_gateway]
  3: [historian, ews, gis, mes, patch_server]
  2: [hmi, scada_server, alarm_server]
  1: [plc, rtu, safety_controller, vfd]
  0: [sensor, actuator, meter]
products:
  ivanti_connect_secure:      {level: 3.5, class: remote_access}
  fortinet_fortigate:         {level: 3.5, class: firewall}
  paloalto_globalprotect:     {level: 3.5, class: remote_access}
  f5_big_ip:                  {level: 3.5, class: remote_access}
  citrix_netscaler:           {level: 3.5, class: remote_access}
  sierra_wireless_airlink:    {level: 3.5, class: cellular_gateway}
  trimble_cityworks:          {level: 3,   class: gis}
  vmware_esxi:                {level: 3,   class: virtualization}
  schneider_altivar:          {level: 1,   class: vfd}
  unitronics_vision:          {level: 1,   class: plc}
  siemens_s7_400:             {level: 1,   class: plc}
  accuenergy_axm:             {level: 0,   class: meter}
```

Enables the question nobody answers with data: **where in the Purdue model does adversary-targeted CVE mass actually sit?** The hypothesis worth testing is that it sits almost entirely at 3.5, not at 1.

### 6.4 Adversary consensus (`enrich/consensus.py`)

For each product: count of distinct, non-overlapping groups that target it. Groups linked by an `overlaps_with` edge collapse into one cluster first, so you are not double-counting the same actor under two vendors' names. Output is a ranked priority list driven by adversary behaviour rather than CVSS.

### 6.5 Telemetry requirement matrix

From the published group-specific hunting guidance, build a table of: hunt technique → required log source → typical collection status in OT → difficulty. Example rows:

| Hunt | Telemetry required | Typically collected in OT? | Difficulty |
|---|---|---|---|
| SOCKS/SOCKS5 tunnel anomaly | East-west NetFlow or span at L3.5 | Rarely | High |
| RDP/SMB proxy tunnel IT→OT | Boundary firewall session logs | Sometimes | Medium |
| EWS industrial software manipulation | Endpoint process + file-write on EWS | Rarely (no EDR on EWS) | High |
| MQTT 8883 sustained C2 | Perimeter flow with port retention | Sometimes | Medium |
| LOTL / PowerShell abuse | PowerShell script-block logging | Almost never | Low to enable |
| VPN session-count outliers | VPN auth logs with baseline | Usually | Low |

This directly answers the JD line about *recommending solutions for telemetry and data visibility gaps*. Score each row and produce a ranked "cheapest visibility wins" list.

---

## 7. Hunt framework

### 7.1 Execution methods

A hunt declares `method: sql | graph | python`. The runner dispatches accordingly and applies the same verdict logic to all three.

| Method | Engine | Used for |
|---|---|---|
| `sql` | SQLite, read-only connection | 1-hop filters and aggregates: H001, H003, H007, H008, H010 |
| `graph` | NetworkX over a projected subgraph | Multi-hop traversal: H009 handoff paths, H004 tool-sharing across clusters, H006 convergence |
| `python` | Registered callable in `hunt/methods/` | Anything needing statistics — medians with confidence intervals, distribution comparisons: H002 |

A `graph` hunt names a projection and an algorithm rather than embedding a query:

```yaml
id: H009
method: graph
projection:
  node_types: [group, tool, vuln, product]
  edge_types: [hands_off_to, uses, exploits, targets]
graph_op:
  fn: descendants_within
  args: {source: sylvanite, depth: 3, via: [hands_off_to, uses, exploits]}
```

**On performance:** the suggestion to swap in DuckDB for speed solves a problem this project does not have. The full graph is on the order of 10⁴–10⁵ CVE rows and a few thousand corpus edges — SQLite handles that without noticing, and the handoff subgraph specifically has four edges. The actual problem with expressing H009 in SQL is **readability**, not throughput: a four-way self-join over an edge table is unreviewable, and unreviewable analysis is untrustworthy analysis. NetworkX fixes the right problem.

DuckDB earns its place only if the timeline work grows into heavy window functions over the full NVD corpus. If that happens, attach it over the same SQLite file via the `sqlite_scanner` extension rather than migrating — SQLite stays the system of record, DuckDB becomes an analytical view. Deferred, not adopted, and the README says why.

### 7.2 Hunt definition format

```yaml
id: H002
title: Time from public PoC to observed OT exploitation, by threat group
hypothesis: >
  Stage 1 initial-access groups targeting OT begin exploiting edge-device
  N-days within 14 days of the first public proof-of-concept.
rationale: >
  Public reporting describes near-immediate weaponisation but supplies no
  measured interval. If true, OT patch SLAs measured in months are
  structurally unable to close the window.
null_hypothesis: >
  Median disclosure-to-observed-use interval exceeds 14 days, or the sample
  is too small to distinguish from chance.
method: sql
query: |
  SELECT g.name,
         COUNT(*)                         AS n,
         MEDIAN(t.disclosure_to_group_use) AS median_days,
         MIN(t.disclosure_to_group_use)    AS fastest
  FROM edge e
  JOIN node g   ON g.id = e.src_node AND g.type = 'group'
  JOIN timeline t ON t.cve = e.dst_node
  WHERE e.rel = 'exploits'
  GROUP BY g.name
  HAVING n >= 3;
falsifies_if: "median_days > 14 OR n < 3"
insufficient_if: "n < 3"
telemetry_gap: >
  t_group_observed derives from public reporting dates, which lag actual
  first use by an unknown interval. Treat every figure as an upper bound.
```

### 7.3 Runner behaviour

`strata hunt run H002` executes, evaluates `falsifies_if` / `insufficient_if`, and emits one of three verdicts:

```
H002  Time from public PoC to observed OT exploitation
──────────────────────────────────────────────────────
VERDICT: INSUFFICIENT DATA  (n=2 groups met the n>=3 threshold)

  SYLVANITE   n=5   median  9d   fastest  2d
  VOLTZITE    n=4   median 31d   fastest 11d
  BAUXITE     n=2   median  —    (below threshold, excluded)

Hypothesis is supported for SYLVANITE and refuted for VOLTZITE.
Public-reporting lag makes all figures upper bounds.
```

`strata hunt run --all` produces the full board. **Refuted and insufficient verdicts are printed with equal prominence to supported ones.** A board that is all green is evidence of a curated dataset, not a good analyst.

### 7.4 The ten hunts

| ID | Hypothesis | Why it matters |
|---|---|---|
| H001 | Edge products targeted by ≥2 non-overlapping group clusters form a small, stable set | Produces an adversary-consensus patch priority list |
| H002 | Stage 1 groups exploit N-days within 14d of public PoC | Quantifies the claim the reports only assert |
| H003 | A vendor fix existed before KEV listing for most OT-relevant CVEs | Reframes the problem from patch availability to patch application |
| H004 | Web shell choice is group-distinctive | **Likely refuted** — Godzilla and GLASSTOKEN appear across clusters. Refuting it undermines shell-based attribution |
| H005 | Ransomware affecting industrials shows no ICS-native protocol involvement | Negative result. The 3,300-org impact runs entirely through IT-side virtualization |
| H006 | Cellular gateway families targeted by ≥2 unrelated state clusters | Tests convergence vs. single-vendor collection bias |
| H007 | Adversary-targeted CVE mass concentrates at Purdue 3.5, not Level 1 | Argues monitoring investment should follow the CVEs, not the mystique |
| H008 | ICS-protocol-native CVE volume is flat while edge CVE volume grows | Trend analysis on your own labelled dataset |
| H009 | Given a Stage 1 TTP, the graph predicts a bounded Stage 2 capability set | Traversal demo — the defender-actionable payoff of modelling handoffs |
| H010 | Vendor patch latency for OT-relevant CVEs varies by >30d across major vendors | Names names, with dates |

H004 and H005 are the ones to lead with in an interview. Being able to say *"I expected X, the data said not-X, here is what I changed"* is the single strongest signal a hunter can give.

---

## 8. Export layer

### 8.1 Synapse Storm generator (`export/storm.py`)

Emits a `.storm` file that would ingest the full graph into a Synapse Cortex. Not executed — generated, syntax-validated, and committed as an artifact.

```storm
// generated by strata export storm — 2026-XX-XX
[ risk:threat=(strata, sylvanite)
    :org.name="Dragos"
    :type=apt
    :name=sylvanite
    .seen=(2023-12-01, 2025-12-31)
]

[ risk:threat=(strata, voltzite) :name=voltzite ]

// initial-access handoff, moderate confidence, src S-0012
[ risk:threat=(strata, sylvanite) ]
  -(hands-off-to)> { risk:threat=(strata, voltzite) }

[ risk:vuln=(cve, "CVE-2025-4427")
    :cve="CVE-2025-4427"
    :cvss:v3_1="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
]
[ risk:threat=(strata, sylvanite) ] -(exploits)> { risk:vuln=(cve, "CVE-2025-4427") }
```

Pair each generated Storm block with the equivalent **query** you would run against it, in `docs/storm-queries.md`:

```storm
// Given a Stage 1 group, what Stage 2 capability should I assume is inbound?
risk:threat:name=sylvanite -(hands-off-to)> risk:threat -(uses)> it:prod:soft

// Which edge products are targeted by more than one threat cluster?
it:prod:softver <(targets)- risk:threat | uniq | count
```

This gets you the Storm conversation in the interview without a Cortex deployment.

### 8.2 STIX 2.1 bundle (`export/stix.py`)

`intrusion-set`, `malware`, `tool`, `attack-pattern`, `vulnerability`, `relationship`. Validated with `stix2-validator`. Proves interoperability with any TIP.

### 8.3 JSON-LD graph

For anyone who wants the raw graph without your tooling. Plus a static Graphviz/D3 render of the handoff model — the single image that explains the project in five seconds.

---

## 9. Security posture

The tool is a security portfolio piece; its own security posture is part of the demo. `SECURITY.md` documents:

**Egress control.** `net.py` wraps `httpx` with a hostname allowlist loaded from `config/allowlist.txt`. Any request to a host not on the list raises before the socket opens. Logged with timestamp, host, and outcome.

```python
ALLOWED = load_allowlist()

def guard(request: httpx.Request) -> None:
    if request.url.host not in ALLOWED:
        raise EgressDenied(f"{request.url.host} not in allowlist")

client = httpx.Client(
    event_hooks={"request": [guard]},
    timeout=30.0,
    follow_redirects=False,          # redirects can escape the allowlist
    headers={"User-Agent": UA},
)
```

`follow_redirects=False` is deliberate. A redirect is an allowlist bypass. Handle them explicitly, re-checking the target.

**No deserialization of untrusted data into code paths.** JSON only, parsed into pydantic models with strict types. No `pickle`, no `yaml.load` (use `yaml.safe_load`), no `eval` in the hunt runner — hunt `falsifies_if` expressions evaluate through a restricted AST evaluator (`simpleeval`) over a fixed variable namespace, not Python `eval`.

**No binary handling.** The pipeline never downloads, stores, or opens an executable. All ingest is JSON, CSV, or text.

**Secrets.** `NVD_API_KEY` from environment only, via pydantic-settings. `.env` in `.gitignore`. Pre-commit hook runs `gitleaks`.

**Supply chain.** `uv.lock` with hashes. `pip-audit` and `ruff` in CI. Dependencies deliberately minimal: `httpx`, `pydantic`, `pydantic-settings`, `typer`, `pyyaml`, `jinja2`, `networkx`, `simpleeval`, `stix2`. No transitive-heavy frameworks.

**Rate limiting and courtesy.** Token bucket per source from `config/sources.toml`. Identifying User-Agent with a contact URL. Conditional requests (`If-None-Match`, `If-Modified-Since`) to avoid refetching. Respect `robots.txt` on any HTML source.

**Reproducibility as an integrity control.** Every raw response written to `data/raw/<source>/<ISO-date>/<sha256>.json` with a sidecar manifest recording URL, status, headers, and fetch time. `--offline` rebuilds the entire database from cache with zero network. Any analytical claim is re-derivable from the snapshot set.

**Containerised run (optional).**

```yaml
# docker-compose.yml
services:
  strata:
    build: .
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    tmpfs: [/tmp]
    volumes:
      - ./data:/app/data
      - ./reports:/app/reports
    environment:
      - NVD_API_KEY
    # no ports published
```

---

## 10. Testing

| Layer | Approach | Target |
|---|---|---|
| Collectors | Frozen fixtures in `tests/fixtures/`, `respx` mocks. No live calls in CI. | 100% of parse paths |
| Normalization | Property tests on CPE parsing with `hypothesis` | Round-trip correctness |
| Protocol classifier | 200-CVE hand-labelled validation set; assert precision ≥ 0.85 | Published in README |
| Enrichment | Golden-file tests on timeline computation | Exact |
| Hunt runner | Each hunt runs against a synthetic fixture DB with a known-correct verdict, including one that must return REFUTED | All 10 |
| Export | `stix2-validator` on the bundle; Storm output parsed by a grammar check | Schema-valid |
| Egress guard | Assert `EgressDenied` raised for off-allowlist host and for a redirect to one | Both cases |

Overall coverage gate: 80%. CI on GitHub Actions, offline-only, no secrets in the workflow.

---

## 11. CLI

```
strata collect [--source NAME] [--since DATE] [--offline]
strata build                               # normalize + load + enrich
strata hunt list
strata hunt run H004 [--format table|json]
strata hunt run --all
strata report                              # renders reports/<date>-assessment.md
strata export storm|stix|jsonld [--out PATH]
strata graph show --group sylvanite --depth 2
strata stats                               # node/edge counts, source coverage, gaps
```

`strata stats` should print collection gaps prominently — sources that failed, vendors with no machine-readable feed, corpus entries with fewer than two independent citations. Surfacing your own gaps is the analytical habit the role is testing for.

---

## 12. The report

`reports/<date>-ot-capability-assessment.md` — 6 to 8 pages, structured as a real intel product, generated from hunt output with hand-written analysis:

1. **Key judgements** — 4 to 6 bullets, each with a confidence level and the hunt ID backing it
2. **Scope and method** — sources, collection window, what was excluded and why
3. **Findings** — one section per hunt, including the refuted ones
4. **Capability handoff model** — the Stage 1 → Stage 2 graph, with the traversal example
5. **Visibility gaps** — the telemetry matrix, ranked by cost-to-close
6. **Confidence and limitations** — reporting lag, collection bias toward vendors with good PSIRTs, sample sizes
7. **Appendix** — full source registry with retrieval dates

Write section 6 seriously. A limitations section that actually limits the findings is rarer than it should be.

---

## 13. Build plan

Roughly 55–65 hours. Sequenced so there is a demoable thing after week 1.

**Week 1 — spine (12h).** Repo, settings, `net.py` with egress guard and cache, SQLite schema with the provenance constraint, KEV and CISA CSAF collectors, `strata stats`. Demoable: real advisory data in a local graph.

**Week 2 — breadth (16h).** NVD, ATT&CK, EPSS, PoC-in-GitHub, ExploitDB, Nuclei, Metasploit collectors. CPE join. Corpus schema and the first three group files with full citations. Tests for every collector.

**Week 3 — the original work (18h).** Protocol classifier plus the 200-CVE labelled validation set. Purdue mapping. Weaponization timeline. Consensus scoring. Remaining group corpus files. This week is the differentiator; do not compress it.

**Week 4 — analysis and packaging (16h).** Ten hunts written and run. Storm and STIX exports. Graph visualization. The report. README with an honest limitations section. Demo script.

---

## 14. Interview delivery

**The 90-second demo.** Terminal. `strata collect --source cisa-kev` pulls live. `strata hunt run H004` returns REFUTED. `strata export storm | head -40` shows the Synapse output. Three commands, all real, no slides.

**The one-line pitch.** *"I read the Year in Review, and built the tracking pipeline I'd want on day one — collection, provenance, and ten falsifiable hunts, four of which came back refuted."*

**The question to ask them.** *"My handoff model treats Stage 1 to Stage 2 as a directed edge with a confidence value. How does Dragos represent that internally — as a relationship between threat groups, or as a property of the intrusion?"* It is a real modeling question, it demonstrates you thought about their taxonomy, and it makes the conversation a peer conversation.

**Legal and ethical framing, stated up front in the README.** The repo reproduces no proprietary report content. Dragos group names are used as public nomenclature with attribution. Every corpus assertion cites a publicly accessible source. No active scanning, no sample handling, no gated content scraped. Say this before anyone asks; it removes the only objection the project could attract.

---

## 15. Frontend — Streamlit

Read-only dashboard over the SQLite database. No writes, no ingest triggers, no shell-outs from the UI. The CLI remains the only thing that mutates state.

### 15.1 Why Streamlit here

Pure Python, so the whole project stays one language and one dependency tree. No node toolchain, no bundler, no CDN fetches — which matters, because a JS frontend pulling from a CDN would punch a hole straight through the egress allowlist in §9. Streamlit serves entirely from local packages.

### 15.2 Layout

```
src/strata/ui/
├── app.py                  # entrypoint: strata ui
├── data.py                 # cached read-only DAO
├── components/
│   ├── verdict_badge.py
│   ├── graph_view.py
│   └── source_footer.py    # renders provenance for any displayed claim
└── pages/
    ├── 1_Hunt_Board.py
    ├── 2_Threat_Groups.py
    ├── 3_Weaponization_Timeline.py
    ├── 4_Protocol_CVEs.py
    ├── 5_Visibility_Gaps.py
    └── 6_Collection_Health.py
```

| Page | Content |
|---|---|
| Hunt Board | All ten hunts as cards with SUPPORTED / REFUTED / INSUFFICIENT badges. Click through to hypothesis, query, result table, and the falsification criterion. Refuted cards are styled with equal weight to supported ones, deliberately. |
| Threat Groups | Select a group → targeted products, exploited CVEs, tools, techniques, handoff edges. Every row shows its source citation inline. |
| Weaponization Timeline | Scatter of `disclosure_to_group_use` by group; box plot of `disclosure_to_poc_days`; filter by Purdue level and sector. |
| Protocol CVEs | The labelled dataset. Volume by protocol over time, plus the confusion matrix from the 200-CVE validation set — showing your own error rate in the UI, not buried in a README. |
| Visibility Gaps | Telemetry matrix sorted by cost-to-close, with the associated hunt technique per row. |
| Collection Health | Per-source last-fetch time, record counts, failures, and corpus entries with fewer than two independent citations. The gaps page. |

### 15.3 Data access

```python
@st.cache_data(ttl=300)
def load_hunts() -> pd.DataFrame:
    with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as con:
        return pd.read_sql("SELECT * FROM hunt_result", con)
```

`mode=ro` on the URI is the enforcement, not a convention. The UI physically cannot write. All queries parameterized; no string interpolation of filter values anywhere.

`mode=ro` alone does not prevent `database is locked` — that comes from WAL mode being set at database creation (§5.5). Use `mode=ro`, not `immutable=1`: a WAL reader needs to touch the `-shm` sidecar, and `immutable` blocks that. Any page reading a mutable metric must go through the point-in-time lookup against `metric_observation`, never a scalar column, or the UI will silently display today's EPSS next to a two-year-old exploitation date.

### 15.4 Hardening

```toml
# .streamlit/config.toml
[server]
address = "127.0.0.1"
port = 8501
headless = true
enableCORS = false
enableXsrfProtection = true
enableStaticServing = false
fileWatcherType = "none"
maxUploadSize = 1

[browser]
gatherUsageStats = false
```

`gatherUsageStats = false` is required — Streamlit reports telemetry to a remote endpoint by default, which contradicts the local-only claim in §1 and would be the first thing a reviewer checks. Binding to `127.0.0.1` keeps it off every other interface. No file upload widget exists anywhere in the app, so `maxUploadSize` is belt-and-braces.

The container in §9 stays portless. Running the UI is an explicit local invocation (`strata ui`), not a published service.

### 15.5 Graph rendering

NetworkX → `pyvis` for the handoff model, rendered to a local HTML string and embedded with `st.components.v1.html`. Pyvis defaults to a CDN for vis.js — set `cdn_resources="local"` so the assets ship from the installed package. Fallback: static Graphviz PNG via `st.image`, which has no network path at all.

### 15.6 Testing

`streamlit.testing.v1.AppTest` drives the pages headlessly in CI against the synthetic fixture database — assert each page renders, the hunt board shows the expected verdict mix including at least one REFUTED, and no page raises on an empty result set. Empty-state handling is the thing that breaks during a live demo.

### 15.7 Demo value

This changes the §14 demo. Terminal for `strata collect` and `strata hunt run H004`, then `strata ui` and screen-share the Hunt Board and Collection Health pages. The Collection Health page is the one to linger on — showing what you failed to collect, live, is a stronger analyst signal than any chart.

---

## 16. Scope discipline

Cut these if time runs short, in this order: vendor PSIRT collectors beyond Siemens, the STIX export, the graph visualization, hunts H006–H008.

Do not cut: the provenance constraint, the protocol classifier validation set, the refuted hunts, the limitations section. Those four are the entire reason the project is worth showing.
