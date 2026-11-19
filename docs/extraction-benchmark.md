---
topic: extraction-benchmark
status: verified
last-updated: 2026-11-18
---

# Extraction size and evidence

From the checkout, run `.venv/Scripts/python.exe -m tools.extraction_benchmark`. Four original synthetic HTML pages distributed under the repository license model an article, a timetable, a sectioned reference and a multi-station data table. Each uses the four content extraction levels with default metadata, links and the 30,000-character limit. The report measures LF-normalized input HTML and the complete paragraph-spotlighted, provenance-wrapped response in UTF-8 bytes. Savings equal one minus response bytes divided by input bytes. Small pages can grow once links and provenance are included. These figures measure bytes on these fixtures only.

Each row checks the returned text for required evidence, including complete table rows and their header. Exit status 1 identifies any missing evidence. On the initial corpus, readability omits the calibration reading on the reference page. The regression test allows that observed omission, accepts its recovery, and fails on new losses, truncation or more than 5% growth against the measured size of any individual response.

## Token measurements

With the optional `tokenizers` Python package installed, pass a name and an existing local Hugging Face `tokenizer.json`. The runner reads the file directly and reports its SHA-256 digest and library version. It counts the full input and returned text with padding, tokenizer truncation and added special tokens disabled. The returned token measurement fixes the generated fetch date and time at 2000-01-01 00:00:00 UTC for reproducibility. All content checks and the cleaner's presentation cap still apply. Measurements exclude model-specific chat framing.

```powershell
.venv/Scripts/python.exe -m tools.extraction_benchmark --tokenizer sentence-transformers/all-MiniLM-L6-v2 --tokenizer-file C:/models/all-MiniLM-L6-v2/tokenizer.json
```

Verified with `tokenizers` 0.22.2 and the WordPiece tokenizer for `sentence-transformers/all-MiniLM-L6-v2`, revision `c9745ed1d9f207416be6d2e6f8de32d1f16199bf`. File SHA-256 is `be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037`.

| Fixture | HTML tokens | Auto response tokens | Required evidence retained |
|---|---:|---:|---|
| Station observations | 1,208 | 702 | Station rows with their values |
| Article | 479 | 261 | Nesting count and survey area |
| Timetable | 563 | 350 | Header and both departures |
| Sectioned reference | 500 | 394 | Calibration and maintenance values |
| **Total** | **2,750** | **1,707** | **4 of 4 checks pass** |

The default view used 37.9% fewer WordPiece tokens across these four fixtures, weighting each by its input length. The reference page illustrates the evidence tradeoff. Readability returned 307 tokens and omitted the calibration value. These counts describe this embedding tokenizer. Supply the tokenizer used by the target model for its text-token measurement.
