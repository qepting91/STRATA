# The 90-second demo

Real commands, terminal + browser, no slides. Everything runs against the
actual local graph; nothing here is staged or mocked.

```bash
uv run strata collect --source kev
uv run strata build
uv run strata ui
```

## Why these three

**1. `strata collect --source kev`** — pulls the live CISA Known
Exploited Vulnerabilities catalog over HTTPS, through the egress
allowlist (`net.py`), and writes real advisory data into the local SQLite
graph. This is the "collection with provenance" half of the pitch: every
row this writes cites a real `source` row with a fetch timestamp and, on
a fresh fetch, a SHA-256 of the payload.

**2. `strata build`** — loads the 26-group, hand-curated Dragos
threat-group corpus (every fact individually cited to
`corpus/citations.yaml`) and runs the enrichment passes: the ICS protocol
classifier, Purdue-level product mapping, the weaponization timeline, and
the MITRE ATT&CK technique/software cross-reference.

**3. `strata ui`** — opens the read-only dashboard. Walk through:
- **Threat Groups** — pick a real, currently-active group (e.g. VOLTZITE
  or KAMACITE) and show the real cited targets/tools/techniques, with the
  live MITRE ATT&CK link on a technique.
- **Analytical Frameworks** — the ICS Cyber Kill Chain stage badges,
  Purdue-level CVE-mass chart, and the Pyramid of Pain honesty mapping
  (this project has real strength at Tools/TTPs and zero at the IOC
  layers — by design, since it never handles malware samples).
- **Threat Hunt Template / Examples** — the reusable hypothesis-driven
  hunting worksheet (hypothesis → Collection Management Framework mapping
  → execution → PROVED/DISPROVED/INCONCLUSIVE), applied for real against
  AZURITE/VOLTZITE/PYROXENE's actual cited data.

## Why there's no automated "hunt board"

An earlier iteration of this project computed ten falsifiable hunts
directly against the graph and rendered a SUPPORTED/REFUTED/INSUFFICIENT
board. That was removed: a *true* threat hunt needs first-party
telemetry (host/network logs, EDR, identity data) to actually prove or
disprove a hypothesis — this project only ever aggregates and correlates
public, open-source reporting, which cannot itself constitute a completed
hunt no matter how the verdict math is dressed up. Presenting a
computed-from-public-data board as if it were real hunt outcomes would
have been a more subtle version of exactly the overclaiming this project
otherwise refuses to do. The real value that remains — provenance-tracked
aggregation, real external citations, and a reusable methodology
worksheet for when you *do* have first-party data — is what "What it
shows" in the README and this demo script actually walk through.

## The one-line pitch

*"I read the Year in Review, and built the tracking and correlation
pipeline I'd want on day one: a provenance-tracked graph joining public
OT/ICS vulnerability data to all 26 Dragos-tracked threat groups' real,
individually-cited behavior, plus the analyst frameworks (Kill Chain,
Purdue, Pyramid of Pain) applied honestly to what that data can and can't
support. I also built and then deliberately removed an automated
'hunt board' once I recognized it was dressing up open-source
correlation as if it were a completed threat hunt — that's the kind of
overclaiming this whole project exists to avoid."*

## The question to ask them

*"My handoff model treats Stage 1 to Stage 2 as a directed edge with a
confidence value. How does Dragos represent that internally — as a
relationship between threat groups, or as a property of the intrusion?"*
It is a real modeling question, it demonstrates you thought about their
taxonomy, and it makes the conversation a peer conversation.

## Legal and ethical framing — say this before anyone asks

This repository reproduces no proprietary threat-intelligence report
content. Threat group names (all 26 Dragos-tracked groups) are public
nomenclature, used with attribution to Dragos's own public threat-group
pages (`dragos.com/threat/*`) — every corpus assertion cites a publicly
accessible source (`corpus/citations.yaml`). No active scanning of any
kind is performed, ever — only HTTPS GETs to a static allowlist of public
feed hosts (`net.py`, `config/allowlist.txt`). No malware samples are
downloaded, stored, or executed. This removes the only objection the
project could attract, and it costs nothing to say up front.
