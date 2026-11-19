---
topic: view-usage
status: verified
last-updated: 2026-11-18
---

# Measuring follow-ups to richer views

Python callers opt in by passing a `ViewUsage` instance to `ResearchFlow(usage=...)`. Share the instance among participating flows in one process for the benchmarking period. Ordinary flows collect nothing. The collector holds integer totals and fixed view names in memory. Discard the collector to end retention. A process restart starts a fresh measurement.

```python
from siftfetch.research_flow import ResearchFlow, ViewUsage

usage = ViewUsage()
with ResearchFlow(usage=usage) as flow:
    first = flow.fetch("https://example.com/")
    if first.handle:
        evidence = flow.read(first.handle, extract="raw")
report = usage.snapshot()
```

| Report field | Meaning |
|---|---|
| `captures` | Successful first reads that returned a reusable snapshot. Each replacement starts a new capture. |
| `escalated_captures` | Number of those captures with at least one successful move to a richer view. Divide by `captures` when positive to get the share. |
| `transitions` | Counts for each observed narrower-to-broader view pair. For example, `{"auto": {"raw": 2}}` represents two successful raw follow-ups directly after auto reads. |

The metric ranks requested extraction breadth from `readability` through `auto`, `full`, `raw` and `source`. Auto may widen the readability extract. Actual response bytes vary by page and are available from `view_sizes`. A successful narrower read becomes the starting point for the next transition. Repeats, size queries and failed reads add zero counts. Increasing `max_chars` on the same view also adds zero. A richer follow-up alone provides no evidence of a failed extraction.
