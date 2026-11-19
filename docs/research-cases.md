---
topic: research-cases
status: verified
last-updated: 2026-11-18
---

# Reviewing potential prompt injections over time

Enable `case_study_sites` in the [local configuration](configuration.md) to start collecting observations. Research evidence stays in the local [site register](site-cases.md) until the owner removes it. Treat every excerpt as untrusted quoted material, including during review by another agent.

## What an observation preserves

Each evidence record links the site and checked source host/path to a bounded excerpt, its category and its review status. The history records each observation in UTC, its origin and the capture time when known. Detector observations carry a grade and detector revision. Several snippets from one detection share an event ID. The first and last observation times describe the retained history. Older aggregate counts cannot supply missing text.

The detector can retain up to ten excerpts of up to 500 characters per acquisition. A Python caller can [report a passage](reported-candidates.md) that the detector missed. Manual reports start unreviewed. Query strings and fragments are removed. Screening can withhold a detector excerpt or reject a manual submission. Review all text for identifying details before quoting it in a paper. A short passage can lose context, and the source can change after capture.

## Local review and export

The evidence command prints JSON with observation history. Use an evidence ID from its output to save a human classification. The status choices are `unreviewed`, `false_positive`, `confirmed_instruction` and `inconclusive`. A confirmed instruction can still be legitimate technical documentation.

```powershell
python -m siftfetch.site_cases evidence --since 2026-10-28
python -m siftfetch.site_cases evidence --site example.org
python -m siftfetch.site_cases classify 12 false_positive
python -m siftfetch.case_trends --since 2026-10-28
```

For a paper, freeze a dated local export and document the collection window, eligibility rules, detector revisions and human review criteria. The trends command groups retained observations by UTC month, origin, detector revision and category. It counts distinct events, sites and evidence records within each group. The report counts observations with a retained excerpt separately from those with metadata alone. An event can appear in multiple categories. These counts describe the collected sample. Estimating prevalence also requires the number and selection of eligible pages examined. To evaluate a detector adjustment, replay the same reviewed examples and benign comparison passages against both revisions.
