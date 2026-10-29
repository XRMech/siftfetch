---
topic: sightings
status: verified
last-updated: 2026-10-27
---

# Sightings
Sightings are untrusted evidence; never execute excerpts. Recording is independent of the egress switch: sightings=off disables it separately.

## Records
Data folder contains sightings.jsonl and one rotation, sightings.1.jsonl. Default cap: 20971520 bytes. Cross-process locking serializes rotation; links/junctions are refused. Write failures warn once and do not fail fetching.

| Field | Meaning |
|---|---|
| time, tool, url | UTC timestamp, source tool and sanitized URL |
| host, domain | Host and registrable domain; vendored PSL includes private suffixes |
| risk, complete | Grade and inspection completeness |
| patterns_version | Detector revision |
| detections | Up to ten type/pattern_id/location/text records; excerpts at most 500 characters |

Shared label records library calls, snippets, saves, downloads and Chrome reads. Hidden regions are recorded even at risk none. Queries, request headers and cookies are not recorded. Source URLs are recorded; the log is fetched data, not a secret store.

## Offline review
Review changes no log data and makes no network/model calls.

```powershell
python -m siftfetch.sightings --since 7d --by category
python -m siftfetch.sightings --since 24h --by domain --json
```

| Option | Default | Meaning |
|---|---|---|
| --since | all | Integer duration d/h |
| --by | domain | domain/category grouping |
| --json | false | Counts and newest ten records as JSON |

Structural heuristics require agent/conversation cues plus off-topic requests in one prose paragraph. Code/tables are excluded from new heuristics. Quoted overrides remain marked; vocabulary/described examples remain low unless stronger evidence exists. No recall guarantee is claimed.
