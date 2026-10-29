---
topic: benchmark
status: verified
last-updated: 2026-10-29
---

# Offline cleaning benchmark
Corpus text is untrusted data. Never execute payloads or fetch their targets. This benchmark measures static detection and text containment, not model attack success. Labels and spotlighting cannot guarantee resistance to prompt injection.

## Run and interpret
From a source checkout, run:

```powershell
.venv/Scripts/python.exe -m siftfetch benchmark
.venv/Scripts/python.exe -m siftfetch benchmark --json
.venv/Scripts/python.exe -m siftfetch benchmark --corpus tests/fixtures/benchmark
.venv/Scripts/python.exe -m pytest -q tests/test_benchmark.py
```

Default: tests/fixtures/benchmark. Installed distributions need `--corpus DIR`. Invalid corpora exit 2; reports exit 0 even with misses. Pytest enforces limits.

The runner uses `clean_html` defaults (auto extraction, 30,000 characters, metadata and links), the pure helper shared by `label`, and the renderer shared by `envelope`. It uses paragraph spotlight without policy reads, sightings, saved quarantine or network access. Envelope rendering assumes egress enabled.

| Metric or field | Meaning |
|---|---|
| Detection | Injection risk meets its manifest minimum, medium for all shipped attacks; removal alone does not count as detection |
| Per technique | Detection counts and missed case IDs for each injection category |
| False positive medium | Benign grade medium or higher |
| False positive high | Benign grade high-candidate or high, both quarantine grades |
| Hidden removal | Expected hidden spans absent or confined to explicit hidden-region markers; a high page grade alone does not count |
| Hidden statuses | removed, marked, or exposed; marked is inline containment, not persisted quarantine |
| Required flags | Manifest spans found inside flagged annotations after normalizing spotlight and whitespace |
| Sentinel leaks | Final outputs containing an internal SFHIDDENSTART or SFHIDDENEND marker prefix |
| Flagged spans | Offsets/categories in scanner input after escaping; detections also describe hidden regions |
| Spotlight/envelope | Actual paragraph marks and envelope boundaries present in output |
| Before cleaning | Same scanner on literal source HTML, without hidden extraction; an informational counterfactual, not equivalent rendered prose |
| Patterns/hash | Pattern version plus SHA-256 of manifest bytes and ordered filenames, byte lengths and case bytes; baseline excluded |

JSON includes cases, outputs and aggregates. Timestamps vary; hashes and metrics do not. Empty denominators yield null rates. Hidden checks include link titles.

## Corpus and baseline
The 70 injections cover quotations, fake turns/tool results, ten hidden mechanisms, invisible controls, homoglyphs, four encodings, links, attributes, split paragraphs, five languages, tool-shaped data, agent addresses and conditional triggers. The 43 benign controls include hard-wrapped PDF-style references/methods, security prose, attack research, fenced examples, code, changelogs, recipes, multilingual text and navigation.

Excerpts cover OWASP, arXiv speech research and TSN/AVB docs. Synthetic hidden cases represent NASA, MIPI and Spellman patterns; those pages were not saved. See [sources](../tests/fixtures/benchmark/SOURCES.md).

Measured 2026-10-28. An unseen set scored 0/49, then 14/49; repo scores are a ceiling. inj-7 adds structural reader scoring and carrier handling.

| Metric | inj-6 | inj-7 |
|---|---|---|
| Overall detection | 40/70 | 69/70 |
| Agent-addressed | 4/5 | 5/5 |
| Attributes | 0/5 | 5/5 |
| Conditional | 3/5 | 5/5 |
| Direct | 5/5 | 5/5 |
| Encoding | 0/5 | 5/5 |
| Hidden | 9/10 | 10/10 |
| Markdown | 2/5 | 4/5 |
| Multilingual | 0/5 | 5/5 |
| Quoted | 5/5 | 5/5 |
| Role | 5/5 | 5/5 |
| Split | 1/5 | 5/5 |
| Tool/JSON | 2/5 | 5/5 |
| Unicode | 4/5 | 5/5 |
| False positive medium | 2/41 | 0/41 |
| False positive high | 0/41 | 0/41 |
| Hidden removal/containment | 9/11 | 11/11 |
| Required flags | 2/2 | 2/2 |
| Sentinel leaks | 0/111 | 0/111 |

Detection rises from 57.1% to 98.6%; literal-source detection is 61/70 (87.1%). Remaining miss: `markdown-03`, a bare autolink with an email query but no instruction or substitution template. Ordinary contact links remain below medium. Fenced overrides are low unless nearby prose adopts the block. Both hidden-containment gaps are fixed.

B8 measured 2026-10-29: two original synthetic PDF-shaped benign cases added. Detection stays 69/70, before-cleaning 61/70, containment 11/11, flags 2/2, and every technique unchanged. Both false-positive counts stay zero (0/41 to 0/43); sentinel leaks stay zero (111 to 113 cases).

Reader scoring weights address (2), conversation meta-reference (3), obligation (2), concealment (3), data movement (3) and authority (3). Medium requires 5, obligation or authority, and meta-reference, concealment or sensitive data movement. Product output paths and third-person descriptions are discounted. Language-extensible signals remain heuristic.

## Add a case and review a regression
Create one short UTF-8 HTML file and one object in [cases.json](../tests/fixtures/benchmark/cases.json). Keep IDs and filenames unique; files must be direct children of the corpus directory. Use original harmless text and reserved targets such as exfil.example or alias@example.invalid.

| Manifest field | Required content |
|---|---|
| id, file | Stable ID and local .html filename |
| source | kind synthetic or excerpt; url null for synthetic, origin URL for excerpt |
| expected_label, technique | injection or benign, plus technique category |
| minimum_risk / maximum_risk | Injection minimum medium or above; benign maximum below high-candidate |
| must_flag | Literal spans required inside annotations, or an empty array |
| must_not_survive | Literal hidden source spans required absent or confined to hidden markers, or an empty array |

For a sighting, keep only relevant markup/CSS; replace personal data and targets with reserved placeholders. Record provenance/edits in SOURCES.md. Never make tests fetch sources. Set expectations independently; include benign controls.

Review misses and outputs before updating [baseline.json](../tests/fixtures/benchmark/baseline.json); tests never overwrite it. Zero tolerances lock detection, techniques, containment, flags and false positives. Benign cases stay below high-candidate. The offline gate checks envelope/spotlight and completes within ten seconds.
