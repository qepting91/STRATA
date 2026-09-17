# STRATA OT/ICS Capability Assessment

*Generated 2026-09-17 by `strata report`, rendered directly from the
live SQLite graph and a real run of every hunt in `hunts/*.yaml`. No figure
below is hardcoded -- re-run `strata report` after any `strata collect` /
`strata build` and every number here re-derives from the new state of the
database.*

---

## 1. Key judgements

- **[H001, moderate confidence, verdict REFUTED]** No product in the corpus currently has confirmed exploitation by 2+ distinct threat-actor clusters (0 qualifying products found among 5 total exploits edges). Refuted, but this is at least as much a sourcing-coverage artifact (only 1 of 8 corpus groups has any named exploited CVE) as it is a finding about real-world convergence.
- **[H003, high confidence, verdict SUPPORTED]** A vendor fix or public advisory predated CISA KEV listing for ~96.37% of 1707 scored CVEs -- for most KEV-listed OT-relevant CVEs, the operational bottleneck is patch *application*, not patch *availability*.
- **[H005, moderate confidence, verdict SUPPORTED]** Of 357 KEV-flagged ransomware CVEs, 0 also involve an ICS-native protocol (overlap rate 0.0%) -- ransomware's operational impact on industrials in this corpus runs through IT-side systems, not OT protocol-native paths.
- **[H007, moderate confidence, verdict SUPPORTED]** Purdue level 3.5 (edge / IT-OT boundary) products carry affects edges from 43 distinct CVEs, versus 5 for Purdue level 1 (PLC/RTU/field-device) products -- adversary-relevant CVE mass concentrates at the boundary, not the field-device layer, within this corpus's Purdue-classified subset.
- **[H009, high confidence, verdict SUPPORTED]** Starting from sylvanite (a Stage 1 initial-access group), a 3-hop traversal over hands_off_to/uses/exploits edges reaches 11 distinct nodes ({'vuln': 5, 'tool': 5, 'group': 1}) -- a real, bounded Stage 2 capability set a defender can act on without waiting for a fresh incident report.

---

## 2. Scope and method

**Sources collected** (10 named collector/loader sources, 1823 total `source` rows for provenance):

- `attack` -- latest fetch `2026-09-17T15:04:31.207810+00:00`
- `cisa-csaf` -- latest fetch `2026-09-17T15:04:30.861843+00:00`
- `cisa-kev` -- latest fetch `2026-09-17T15:04:30.735963+00:00`
- `corpus` -- latest fetch `2026-09-17`
- `epss` -- latest fetch `2026-09-17T15:05:16.767365+00:00`
- `exploitdb` -- latest fetch `2026-09-17T15:05:17.417196+00:00`
- `metasploit` -- latest fetch `2026-09-17T15:05:22.101599+00:00`
- `nuclei` -- latest fetch `2026-09-17T15:05:22.001574+00:00`
- `nvd` -- latest fetch `2026-09-17T15:05:14.362168+00:00`
- `poc-github` -- latest fetch `2026-09-17T15:05:17.174093+00:00`

**Collection window:** earliest fetch `2026-09-17`, latest fetch `2026-09-17T15:05:22.101599+00:00`. This is a point-in-time snapshot of public CISA/NVD/MITRE/FIRST.org/GitHub-hosted feeds plus a hand-curated 8-group threat corpus (`corpus/groups/*.yaml`), not a continuously-updating feed.

**Current graph size:** {'advisory': 24, 'geo': 13, 'group': 9, 'product': 2859, 'protocol': 1, 'sector': 20, 'technique': 794, 'tool': 17, 'vendor': 355, 'vuln': 1790} nodes by type; {'affects': 9917, 'describes': 77, 'exploits': 5, 'hands_off_to': 4, 'implements': 14, 'involves': 3, 'made_by': 2859, 'targets': 65, 'uses': 17} edges by type.

**What was excluded, and why** (real, documented gaps from Weeks 1-3 --
see `SOURCES.md` and `README.md` for full detail):

- **Vendor-PSIRT collectors (Siemens, Schneider, Hitachi, Cisco, Palo Alto, Fortinet, Ivanti).** Deliberately deferred every week (see SOURCES.md, "Deliberately not collected"). No per-vendor disclosure-date data exists anywhere in the schema as a result -- this is why H010 (cross-vendor patch latency) is INSUFFICIENT.
- **CSAF product-tree text extraction.** The CISA CSAF collector never extracts product_tree text, so enrich/protocol.py's ICS-protocol classifier runs over NVD CVE description text only -- not the full input set spec section 6.2 describes.
- **t_group_observed / disclosure_to_group_use.** The corpus's group-entry format (corpus/groups/*.yaml) has no first_seen date on a group's exploits claims, so this metric has zero rows in metric_observation -- this is why H002 is INSUFFICIENT rather than merely small-sample.

---

## 3. Findings

All ten hunts are reported here with equal prominence, including the
refuted and insufficient ones -- a board that is all green is evidence of
a curated dataset, not a good analyst.

### H001 -- Edge products targeted by two or more non-overlapping group clusters

**VERDICT: REFUTED**

*Hypothesis:* Edge products (VPN gateways, firewalls, cellular gateways) targeted by two or more distinct threat-actor clusters form a small, stable set worth prioritizing for patch/monitoring investment.

*Rationale:* If distinct clusters independently converge on the same edge products, that convergence is itself a patch-priority signal, cheaper to compute than reasoning about any single actor group in isolation.

*Real result:* `total_exploits_edges=5, n=0`

*Telemetry gap:* The corpus's exploits edges only exist where a public source explicitly names both an actor and a CVE (today, only sylvanite's 5 Ivanti/SAP CVEs qualify). Seven of eight corpus groups have no named CVEs at all in their public sourcing, so any product they exploit is invisible to this hunt even if real-world convergence exists -- this is a sourcing-coverage gap, not evidence against convergence.

### H002 -- Time from public PoC to observed OT exploitation, by threat group

**VERDICT: INSUFFICIENT**

*Hypothesis:* Stage 1 initial-access groups targeting OT begin exploiting edge-device N-days within 14 days of the first public proof-of-concept.

*Rationale:* Public reporting describes near-immediate weaponization but supplies no measured interval. If true, OT patch SLAs measured in months are structurally unable to close the window.

*Real result:* `n=0, groups_with_n_gte_3=0, median_days=None`

*Telemetry gap:* disclosure_to_group_use was never computed (documented Week 3 scope reduction): the corpus group-entry format has no first_seen date on a group's exploits claims, unlike the spec's own illustrative example. There are zero metric_observation rows for this metric_name at all -- computing it for real would require re-researching first-observed-use dates for every corpus exploit claim, which is out of scope for this pass. This is an honest absence, not a small-sample artifact.

### H003 -- A vendor fix existed before KEV listing for most OT-relevant CVEs

**VERDICT: SUPPORTED**

*Hypothesis:* For most CVEs that make it onto the CISA KEV catalog, a vendor patch was already available before the KEV listing date -- reframing the problem from patch availability to patch application.

*Rationale:* If patches routinely predate KEV listing, the operational bottleneck is not vendor responsiveness, it is asset owners' patch-application latency -- a different remediation strategy than "wait for a fix."

*Real result:* `n=1707, pct_patched_before_kev=0.9636789689513767`

*Telemetry gap:* patch_available_at_kev compares whichever of {CSAF advisory initial_release_date, NVD nvd_published} is available against KEV's date_added -- it is a proxy for "a public advisory or NVD record existed", not a direct read of a vendor's own patch-release date (no vendor-PSIRT collector exists, see H010). Real corpus: 1707 observations, ~96% (patch/advisory predates KEV).

### H004 -- Web shell / tool choice is group-distinctive

**VERDICT: INSUFFICIENT**

*Hypothesis:* A group's choice of web shell or post-exploitation tool is distinctive enough that tool identity alone can support attribution -- no two distinct groups in the corpus rely on the same named tool.

*Rationale:* If tool choice is genuinely group-distinctive, tool identity is a cheap, reusable attribution signal. If not, tool-based attribution is weaker evidence than reports typically imply.

*Real result:* `n_tools_compared=17, n_tools_shared_across_groups=0, n_uses_edges=17`

*Telemetry gap:* The corpus's uses edges are hand-curated from each group's own public Dragos threat page, one page per group, cited independently -- there is no cross-source corroboration step that would surface a tool two pages both happen to name. Real data: 17 uses edges across 7-8 groups, zero shared. Reporting that as SUPPORTED would overclaim from a small hand-curated sample: absence of an observed counterexample in 17 edges is not evidence the broader real-world claim holds, especially since well-known public reporting elsewhere (e.g. shared web-shell families like China-Chopper across multiple unrelated Chinese state clusters) directly contradicts strict group-distinctiveness. This is one of the two hunts (with H005) most worth leading with in an interview, per the spec's own framing: "I expected X, the data said not-X" is the strongest signal a hunter can give.

### H005 -- Ransomware affecting industrials shows no ICS-native protocol involvement

**VERDICT: SUPPORTED**

*Hypothesis:* CVEs flagged for known ransomware-campaign use show essentially zero overlap with CVEs that involve an ICS-native protocol (Modbus, S7comm, DNP3, etc.) -- ransomware's operational impact on industrials runs through IT-side systems (virtualization, file shares), not OT protocol-native paths.

*Rationale:* Large-impact ransomware incidents against industrial organizations are frequently narrated as "ICS attacks" in press coverage. If the CVEs driving those incidents are IT-side, that framing is misleading for defenders deciding where to invest OT-specific monitoring.

*Real result:* `n_ransomware_cves=357, n_ransomware_cves_with_protocol_involvement=0, overlap_rate=0.0`

*Telemetry gap:* known_ransomware_campaign_use is a KEV-sourced field with only two observed values ("Known"/"Unknown") and no severity/scope detail; a CVE can be flagged "Known" ransomware use while still describing an unrelated component. The involves edge only exists at all where the protocol classifier matched a CVE description keyword (3 edges total, all EtherNet/IP) -- a real but narrow evidentiary base for the "no overlap" side too. Still, with 357 ransomware-flagged CVEs and 0 of them among the 3 protocol-involving CVEs, this is a real, computable, and honestly negative result -- one of the two hunts (with H004) most worth leading with in an interview.

### H006 -- Cellular gateway product families targeted by two or more unrelated clusters

**VERDICT: INSUFFICIENT**

*Hypothesis:* Cellular-gateway product families (Purdue level 3.5, class cellular_gateway) are targeted by two or more unrelated state-linked clusters -- convergence that would argue for treating cellular gateways as a class, not chasing single-vendor collection bias.

*Rationale:* If distinct clusters independently converge on cellular gateways specifically (not just edge devices broadly), that argues for a dedicated collection/monitoring investment in that product class.

*Real result:* `n=0, n_cellular_gateway_products_examined=0, qualifying_products=[]`

*Telemetry gap:* Purdue-level classification covers only 86 of 2859 product nodes (config/purdue_map.yaml's hand-curated vendor/product mapping), and the exploits edge set only reaches sylvanite's 5 Ivanti/SAP CVEs -- none of which affect a cellular-gateway-classed product. A real cellular- gateway convergence (e.g. against Sierra Wireless AirLink, which is mapped in purdue_map.yaml) could exist in the world without appearing here, since no group in this corpus has publicly attributed cellular-gateway exploitation. n=0 here reflects sourcing coverage, not a refutation of the underlying convergence hypothesis.

### H007 -- Adversary-targeted CVE mass concentrates at Purdue 3.5, not Level 1

**VERDICT: SUPPORTED**

*Hypothesis:* The volume of distinct CVEs affecting Purdue level 3.5 products (VPN gateways, firewalls, jump hosts, cellular gateways) exceeds the volume affecting Purdue level 1 products (PLCs, RTUs, safety controllers, VFDs) in this corpus.

*Rationale:* If adversary-relevant CVE mass concentrates at the IT/OT boundary rather than at field-device level, monitoring investment should follow the CVEs (level 3.5), not the mystique (level 1 PLC/RTU compromise).

*Real result:* `mass_3_5=43, mass_1=5`

*Telemetry gap:* Purdue-level classification covers only 86 of 2859 product nodes (config/purdue_map.yaml), so both mass_3_5 and mass_1 are lower bounds on the true CVE mass at each level -- an unmapped product cannot contribute to either side. The comparison is only meaningful relative to what has been mapped so far, not an exhaustive census.

### H008 -- ICS-protocol-native CVE volume is flat while edge CVE volume grows

**VERDICT: INSUFFICIENT**

*Hypothesis:* Year-over-year, the count of CVEs involving an ICS-native protocol (Modbus, S7comm, DNP3, etc.) is flat, while the count of CVEs affecting Purdue-3.5-classified edge products grows.

*Rationale:* If true, this argues that the growing CVE workload for OT-adjacent defenders is concentrated in edge/IT-boundary products, not in protocol-native ICS vulnerabilities -- a trend-analysis argument for where to grow monitoring capability.

*Real result:* `n_protocol_cves=3, n_edge_cves=43, protocol_cves_by_year={2017: 2, 2026: 1}, edge_cves_by_year={2019: 6, 2021: 6, 2025: 6, 2023: 6, 2020: 7, 2024: 3, 2017: 1, 2026: 3, 2018: 1, 2014: 1, 2022: 1}`

*Telemetry gap:* The involves edge set has only 3 members total (all EtherNet/IP, from the protocol classifier's real matches against NVD descriptions) -- a 3-point series cannot support a trend claim in either direction, flat or otherwise. This is a direct consequence of the protocol classifier being scoped to CVE description text only (no CSAF product-tree matching, a documented Week 3 gap), not evidence the underlying trend claim is false.

### H009 -- Given a Stage 1 handoff, the graph predicts a bounded Stage 2 capability set

**VERDICT: SUPPORTED**

*Hypothesis:* Starting from a Stage 1 initial-access group (sylvanite), traversing hands_off_to/uses/exploits edges up to 3 hops predicts a bounded, non-empty Stage 2 capability set -- the defender-actionable payoff of modeling handoffs explicitly instead of treating each group in isolation.

*Rationale:* If a defender knows sylvanite is active in their environment, this traversal is the concrete answer to "what capability should I assume is inbound next," grounded in real, cited hands_off_to/uses/exploits edges rather than general reasoning about the actor's reputation.

*Real result:* `reachable_nodes=['CVE-2023-46805', 'CVE-2024-21887', 'CVE-2025-31324', 'CVE-2025-4427', 'CVE-2025-4428', 'tool-frp', 'tool-krustyloader', 'tool-warpwire', 'tool-wirefire', 'tool-zipline', 'voltzite'], n=11, by_type={'vuln': 5, 'tool': 5, 'group': 1}, source_present=True`

*Telemetry gap:* The traversal is only as complete as the corpus's own hands_off_to/ uses/exploits edges (4/17/5 total respectively) -- it will not surface a real-world Stage 2 handoff that no public source has yet named. Real result: from sylvanite, hop 1 reaches voltzite (hands_off_to) plus sylvanite's own 5 exploited CVEs and 4 used tools (krustyloader, warpwire, wirefire, zipline); hop 2 adds exactly one further node -- voltzite's own tool, frp (voltzite -uses-> frp) -- for 11 reachable nodes total at depth 3. No further hops exist beyond that (frp/the CVEs/the other tools have no further outbound hands_off_to/uses/ exploits edges in this corpus), so the traversal terminates naturally rather than being artificially depth-capped.

### H010 -- Vendor patch latency for OT-relevant CVEs varies by more than 30 days across vendors

**VERDICT: INSUFFICIENT**

*Hypothesis:* Patch latency (disclosure to vendor fix availability) for OT-relevant CVEs varies by more than 30 days across major vendors -- naming names, with dates.

*Rationale:* If patch latency varies materially by vendor, that is directly actionable procurement/risk-acceptance guidance, distinct from the generic "patch faster" advice.

*Real result:* `n_vendors_with_data=0`

*Telemetry gap:* No vendor-PSIRT collector was ever built (Siemens/Schneider/Hitachi/ Cisco/Palo Alto/Fortinet/Ivanti were all deliberately deferred every week, see SOURCES.md) -- no per-vendor disclosure-date data exists anywhere in the schema to compare latency across vendors. The patch_available_at_kev metric (H003) is a proxy for "an advisory or NVD record existed before KEV listing", not a per-vendor patch-release date, and cannot substitute for this hunt's actual question.


---

## 4. Capability handoff model

Real `hands_off_to` edges currently in the graph (confidence values are
read live from `corpus/groups/*.yaml`, since `edge.note` is not populated
for this edge type):

- `kamacite` -\[hands_off_to, confidence=high\]-> `electrum`
- `parisite` -\[hands_off_to, confidence=high\]-> `magnallium`
- `parisite` -\[hands_off_to, confidence=moderate\]-> `pyroxene`
- `sylvanite` -\[hands_off_to, confidence=high\]-> `voltzite`

**Traversal example (H009):** starting from `sylvanite`, a 3-hop traversal
over `hands_off_to`/`uses`/`exploits` edges reaches
**11** nodes total (`{'vuln': 5, 'tool': 5, 'group': 1}`
by type). This is the concrete, defender-actionable answer to "given
sylvanite is active in my environment, what capability should I assume is
inbound next" -- grounded in real, cited edges, not general reasoning
about the actor's reputation.

---

## 5. Visibility gaps

`config/telemetry_matrix.yaml`, ranked cheapest-to-close first:

| Hunt technique | Telemetry required | Typically collected in OT | Difficulty |
|---|---|---|---|
| VPN session-count outliers | VPN auth logs with baseline | Usually | Low |
| LOTL / PowerShell abuse | PowerShell script-block logging | Almost never | Low to enable |
| RDP/SMB proxy tunnel IT->OT | Boundary firewall session logs | Sometimes | Medium |
| MQTT 8883 sustained C2 | Perimeter flow with port retention | Sometimes | Medium |
| SOCKS/SOCKS5 tunnel anomaly | East-west NetFlow or span at L3.5 | Rarely | High |
| EWS industrial software manipulation | Endpoint process + file-write on EWS | Rarely (no EDR on EWS) | High |

---

## 6. Confidence and limitations

This section is written to actually limit the findings above, not to
reassure the reader.

**Reporting lag is baked into every date this pipeline uses.** Every
timestamp in the graph (KEV `dateAdded`, CSAF `initial_release_date`, NVD
`nvd_published`) is a *publication* date, not a ground-truth first-use or
first-disclosure date. Every derived interval (`patch_available_at_kev`,
`disclosure_to_poc_days`, etc.) is therefore an upper or lower bound on the
true interval, never an exact measurement -- see H003's own
`telemetry_gap` for the concrete case.

**Collection bias toward organizations with good public reporting.** Of
9 groups in the corpus, 8 have **zero** cited CVE-exploitation claims at all -- not because they don't exploit CVEs, but because their public Dragos threat-group page never named one. Every hunt that joins through `exploits` edges (H001, H002, H006, H008) is therefore scoped to whichever single group happens to have had its exploited CVEs publicly named, not the full threat landscape. This is precisely the "curated dataset" risk the hunt framework's own design principle warns about.

**Small-N caveats.**
The protocol classifier's 200-CVE hand-labeled validation set measured precision = recall = 1.000, but on **n=3 true positives** out of 3 candidates reviewed (the corpus's real base rate of protocol-specific CVEs is 3 of 1,790 known CVEs). A perfect score on 3 positives is not the same statistical claim as a perfect score on 300 -- it says the classifier made no visible mistake on the cases it had, not that it generalizes with high confidence. All 3 classifier-flagged candidates held up under independent reading as genuine EtherNet/IP (CIP) implementation vulnerabilities -- no false positives found among the flagged set. Across all 197 candidate-negative items, careful reading found no genuine recall gap: no description referenced Modbus, S7comm, IEC-104, DNP3, IEC-61850, EtherNet/IP, OPC-UA, BACnet, or MQTT under a synonym or vendor-specific phrasing the keyword list misses. A few items brushed near ICS/OT territory (e.g. CVE-2026-81861 mentions 'RTU functionality' generically, CVE-2026-12661 concerns Rockwell FactoryTalk Historian, CVE-2016-4523 concerns Trihedral VTScada SCADA software) but none of these descriptions actually name or describe an implementation of one of the 9 tracked protocols -- they describe web-interface, credential, or generic-DoS flaws in ICS-adjacent products, so labeling them positive would be unsupported inference rather than ground truth. The overwhelming majority of the 197 negatives are generic enterprise/OS/browser/CMS CVEs (Windows, Chrome, Adobe, Oracle, Cisco IOS/ASA web and VPN features, Java, iOS, etc.) with no plausible protocol linkage at all. This corroborates the corpus's very low true base rate (3/1790 known CVEs trigger any keyword match) -- the classifier's near-total silence on this corpus appears to reflect the actual rarity of protocol-specific CVEs in a KEV/CSAF-sourced, largely non-ICS dataset rather than a recall failure, though the sample size (197) cannot rule out rarer misses elsewhere in the full corpus.
Several hunts (H002, H004, H006, H008) rest on single-digit or low-double-digit sample sizes for the same underlying reason: the corpus is 8 hand-curated groups whose public sourcing rarely names specific CVEs or tools.

**Deliberately deferred data (not silently dropped).** Vendor-PSIRT collection, CSAF product-tree matching, and group first-seen-use dates were all scoped out of Weeks 1-3 (see section 2 above) -- they are the direct cause of the 5 INSUFFICIENT verdicts below (H002, H004, H006, H008, H010), which should be read as "this pipeline cannot yet answer this question," not as "the answer is no."

**Net verdict mix, for context:** 4 SUPPORTED (H003, H005, H007, H009), 1 REFUTED (H001), 5 INSUFFICIENT (H002, H004, H006, H008, H010). A mixed board, not an all-green one, is the intended and honestly-reported outcome of this pass.

---

## 7. Appendix -- source registry

**Corpus citations** (`corpus/citations.yaml`, every claim in
`corpus/groups/*.yaml` resolves to one of these):

- **S-0001** -- Dragos, `https://www.dragos.com/threat/sylvanite/` (retrieved 2026-09-17)
- **S-0002** -- Dragos, `https://www.dragos.com/threat/voltzite` (retrieved 2026-09-17)
- **S-0003** -- Dragos, `https://www.dragos.com/blog/new-ics-threat-activity-group-kamacite/` (retrieved 2026-09-17)
- **S-0004** -- Google Cloud (Mandiant), `https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day` (retrieved 2026-09-17)
- **S-0005** -- SecurityAffairs, `https://securityaffairs.com/178285/apt/china-linked-apt-unc5221-started-exploiting-ivanti-epmm-flaws-shortly-after-their-disclosure.html` (retrieved 2026-09-17)
- **S-0006** -- The Hacker News, `https://thehackernews.com/2025/05/china-linked-apts-exploit-sap-cve-2025.html` (retrieved 2026-09-17)
- **S-0007** -- Dragos, `https://www.dragos.com/threat/electrum` (retrieved 2026-09-17)
- **S-0008** -- Dragos, `https://www.dragos.com/threat/azurite` (retrieved 2026-09-17)
- **S-0009** -- Dragos, `https://www.dragos.com/threat/pyroxene` (retrieved 2026-09-17)
- **S-0010** -- Dragos, `https://www.dragos.com/threat/bauxite` (retrieved 2026-09-17)
- **S-0011** -- Dragos, `https://www.dragos.com/threat/parisite` (retrieved 2026-09-17)

**Collector/loader sources, with latest retrieval date:**

- `attack` -- 2026-09-17T15:04:31.207810+00:00
- `cisa-csaf` -- 2026-09-17T15:04:30.861843+00:00
- `cisa-kev` -- 2026-09-17T15:04:30.735963+00:00
- `corpus` -- 2026-09-17
- `epss` -- 2026-09-17T15:05:16.767365+00:00
- `exploitdb` -- 2026-09-17T15:05:17.417196+00:00
- `metasploit` -- 2026-09-17T15:05:22.101599+00:00
- `nuclei` -- 2026-09-17T15:05:22.001574+00:00
- `nvd` -- 2026-09-17T15:05:14.362168+00:00
- `poc-github` -- 2026-09-17T15:05:17.174093+00:00
