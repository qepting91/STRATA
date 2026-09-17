# Storm queries against the STRATA-generated Cortex data

`strata export storm` (`src/strata/export/storm.py`) writes a `.storm`
file that would ingest the group/vuln/tool/technique portion of the
STRATA graph into a Synapse Cortex. It is **generated and
syntax-checked, never executed** against a real Cortex (see
`strata-engineering-spec.md` section 8.1 and `SECURITY.md` for why: this
project is local-only and does not depend on, or ship, a Synapse
deployment).

This file pairs each real STRATA question with the Storm query you would
run once the generated data is actually ingested into a Cortex.

## 1. Given a Stage 1 group, what Stage 2 capability should I assume is inbound?

```storm
// The same question `strata graph show` answers via a networkx
// traversal, as a live Cortex query instead -- same edges, same answer.
risk:threat:name=sylvanite -(hands-off-to)> risk:threat -(uses)> it:prod:soft
```

Against the real corpus this resolves to `voltzite` at hop 1, then
`frp` (voltzite's own tool) at hop 2 -- exactly what
`strata graph show --group sylvanite --depth 2` prints today.

## 2. Which edge products are targeted by more than one threat cluster?

```storm
// Which edge products are exploited by more than one distinct threat cluster?
it:prod:softver <(targets)- risk:threat | uniq | count
```

Real data note: our corpus's `exploits` edges reach a CVE, not a product
directly, and only sylvanite has any `exploits` edges at all today -- so
this specific query would need `risk:vuln <(targets)- risk:threat
-(targets)> it:prod:softver` chained through the CVE, not the single-hop
form shown in the spec's own illustrative worked example. Both forms are
shown here deliberately, since a reader ingesting the real generated
`.storm` file would hit exactly this same real-data gap.

## 3. What is the evidentiary basis for a given hands_off_to edge?

```storm
// Every hands_off_to edge in the generated .storm file carries a
// "// evidence: <note>" comment immediately above it where a note was
// recorded (see enrich/protocol.py's analogous involves-edge evidence
// pattern) -- in a real Cortex this maps to a tag or property on the
// edge node, e.g.:
risk:threat:name=sylvanite -(hands-off-to)> risk:threat:name=voltzite
| limit 1
```
