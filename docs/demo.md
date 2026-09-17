# The 90-second demo

Three real commands, terminal only, no slides — per
`strata-engineering-spec.md` §14. All three run against the actual local
graph; nothing here is staged or mocked.

```bash
uv run strata collect --source kev
uv run strata hunt run H004
uv run strata export storm --out data/export/strata.storm && head -40 data/export/strata.storm
```

(The spec's own §14 script writes `--source cisa-kev` and
`strata export storm | head -40`; this implementation's actual
`SourceChoice` enum value is `kev` — see `cli.py`'s `_COLLECTOR_REGISTRY`
— and `strata export storm` writes to a file rather than stdout, so the
second command pipes to `head` after the fact. Both are the real,
runnable commands for this codebase, not the spec's illustrative
phrasing.)

## Why these three, and one honest adjustment from the spec

**1. `strata collect --source cisa-kev`** — pulls the live CISA Known
Exploited Vulnerabilities catalog over HTTPS, through the egress
allowlist (`net.py`), and writes real advisory data into the local SQLite
graph. This is the "collection with provenance" half of the pitch: every
row this writes cites a real `source` row with a fetch timestamp and, on
a fresh fetch, a SHA-256 of the payload.

**2. `strata hunt run H004`** — the spec's own §14 script names H004 as
the hunt to lead with, on the expectation it would come back **REFUTED**
("Godzilla and GLASSTOKEN appear across clusters"). Running the real
pipeline against the real, hand-curated 8-group corpus, **H004 actually
comes back INSUFFICIENT, not REFUTED** — the corpus's `uses` edges show
17 tool/group pairings with zero tools shared across groups, but that
absence is a function of a small, hand-curated, single-source-per-group
sample (each group's tooling is cited to one Dragos page), not a
statistically supported claim that tool choice is truly group-distinctive
in the real world. Publicly reported cases like China-Chopper turning up
across multiple unrelated Chinese state clusters directly argue the other
way. Reporting this as REFUTED (or, worse, as SUPPORTED) would overclaim
from n=17 hand-curated edges — so the hunt's own `insufficient_if:
n_tools_compared < 20` threshold catches it honestly. **This is still the
right hunt to lead with**: saying "I expected this to plausibly refute
group-distinctive attribution, the data said the sample can't support
either conclusion, and here's exactly why" is a stronger interview signal
than a clean REFUTED would have been — it demonstrates the same
falsifiable-hypothesis discipline the spec is testing for, plus the
extra step of recognizing when your own sample size doesn't license a
verdict either way.

(H005 — "ransomware affecting industrials shows no ICS-native protocol
involvement" — is the other hunt worth having in your back pocket: it
comes back **SUPPORTED**, a real, computable negative result over 357
KEV-flagged ransomware CVEs and 0 of them among the corpus's 3
protocol-involving CVEs. Run `uv run strata hunt run H005` as a follow-up
if asked for a SUPPORTED example instead of an INSUFFICIENT one.)

**3. `strata export storm --out ... && head -40 ...`** — generates a Synapse Storm
ingest script from the real graph (group/vuln/tool/technique nodes and
their `hands_off_to`/`uses`/`exploits`/`implements` edges) and prints the
first 40 lines. This is not executed against a real Cortex — it is
generated and syntax-checked (see `docs/storm-queries.md` for the paired
queries you would run once ingested) — but it proves the data model maps
cleanly onto a real TIP's ingest format, without needing to stand one up
for the interview.

## The one-line pitch

*"I read the Year in Review, and built the tracking pipeline I'd want on
day one — collection with provenance, ten falsifiable hunts, and an
honestly mixed board: four supported, one refuted, and five reported
INSUFFICIENT rather than forced to a verdict the data can't support. That
last part is the point — a board that's all green is evidence of a
curated dataset, not a good analyst."*

(This is the honest version of the spec's own illustrative pitch, which
guessed "four of which came back refuted" before any real data existed.
The real board is 4 SUPPORTED / 1 REFUTED / 5 INSUFFICIENT — arguably a
*stronger* honesty signal than the spec's hypothetical, since reporting
five INSUFFICIENT verdicts instead of forcing them into REFUTED/SUPPORTED
is exactly the discipline the role is testing for.)

## The question to ask them

*"My handoff model treats Stage 1 to Stage 2 as a directed edge with a
confidence value. How does Dragos represent that internally — as a
relationship between threat groups, or as a property of the intrusion?"*
It is a real modeling question, it demonstrates you thought about their
taxonomy, and it makes the conversation a peer conversation.

## Legal and ethical framing — say this before anyone asks

This repository reproduces no proprietary threat-intelligence report
content. Threat group names (SYLVANITE, VOLTZITE, KAMACITE, ELECTRUM,
AZURITE, PYROXENE, BAUXITE, PARISITE) are public nomenclature, used with
attribution to Dragos's own public threat-group pages
(`dragos.com/threat/*`) — every corpus assertion cites a publicly
accessible source (`corpus/citations.yaml`). No active scanning of any
kind is performed, ever — only HTTPS GETs to a static allowlist of public
feed hosts (`net.py`, `config/allowlist.txt`). No malware samples are
downloaded, stored, or executed. This removes the only objection the
project could attract, and it costs nothing to say up front.
