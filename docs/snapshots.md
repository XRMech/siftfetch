---
topic: snapshots
status: verified
last-updated: 2026-11-18
---

# Public HTML snapshots

Use `ResearchFlow` for anonymous follow-up reads. Use [usage counts](view-usage.md), [web images](web-images.md), [static panels](snapshot-panels.md), the [offline browser viewport](live-navigation.md) and [guarded next-page links](pagination.md) with the same eligible capture. To report a missing fact, see [local site registers](site-cases.md).

```python
from siftfetch.research_flow import ResearchFlow

with ResearchFlow() as flow:
    first = flow.fetch("https://example.com/")
    if first.handle:
        sizes = flow.view_sizes(first.handle)
        source = flow.read(first.handle, extract="source")
```

Each read returns enveloped `content`, an optional opaque `handle`, and UTC `captured_at`. Follow-ups reuse the capture and timestamp. Eligible pages are successful direct public HTTPS HTML responses explicitly marked public. Redirects, local endpoints, URLs with user information, queries or fragments, cookies, private/no-store/no-cache responses, browser and alternate-source recovery stay call-only.

A successful fetch replaces the flow's previous capture. Release it with `flow.release()`, close the flow with `flow.close()`, or use the context manager. Unknown, foreign, released and expired handles raise `KeyError` without fetching. Initial process-local limits are 60 seconds idle, one capture per flow, 32 total captures, 2 MiB per capture and 32 MiB total for retained HTML and URL strings. Reads refresh idle time. Under memory pressure, the capture idle longest is evicted first. An oversized page still returns its first read.

Follow-up views include inert, labeled decoded HTML (`source`). Pass `max_chars` to `read` or `view_sizes` (default 30,000, zero for unlimited). `truncated` reports presentation clipping (unknown for some call-only fallbacks). Capped source shows the character count and marks the scan incomplete. `size_bytes` measures the enveloped content in UTF-8. `view_sizes` renders all five views locally under current policy without recording sightings.
