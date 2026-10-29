---
topic: index
status: verified
last-updated: 2026-10-28
---

# Documentation
SiftFetch cleans incoming web content: hidden-text stripping, injection scanning and risk grading, structural and suspected spans, spotlighting, untrusted-content envelopes, and a sightings log. Outbound value checks protect outgoing data. Optional Lockdown and setup tooling add controls; labels cannot prevent every injection.

| Document | Read when |
|---|---|
| [Library](library-api.md) | Integrate Python |
| [API detail](api/index.md) | Inspect options and results |
| [MCP](mcp-tools.md) | Call tools |
| [Hook](hook.md) | Understand limits |
| [Threat model](threat-model.md) | Review boundaries and open research |
| [Configuration](configuration.md) | Change policy |
| [Environment](environment.md) | Configure host processes |
| [Sightings](sightings.md) | Review detections |
| [CLI](cli.md) | Run setup commands |
| [Setup](setup/index.md) | Install clients |
| [Testing](testing.md) | Run checks |
| [Benchmark](benchmark.md) | Measure cleaning regressions |
| [Writing](writing-docs.md) | Edit docs |

| Term | Meaning |
|---|---|
| Policy folder | Owner-only identifiers/settings |
| Data folder | Readable artifacts/logs |
| Substitute | Approved identity to disclose |
| Envelope | Untrusted-content boundary/grade |
| Spotlight | Prose provenance marks |
| Grant | Scoped disclosure permission |
| Quarantine | Artifact held for owner review |
