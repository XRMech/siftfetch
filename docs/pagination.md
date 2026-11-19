---
topic: pagination
status: verified
last-updated: 2026-11-18
---

# Follow a declared next page

A Python caller can inspect a public [research flow capture](library-api.md#public-html-snapshots) for same-origin pagination and request one selected link. A page's `rel=next` is an untrusted claim about its destination. Inspect the labeled destinations before choosing one. The destination server controls the effects of a GET.

```python
from siftfetch.pagination import follow_next, pagination_inventory
from siftfetch.research_flow import ResearchFlow

with ResearchFlow() as flow:
    first = flow.fetch("https://example.com/reports")
    if first.handle:
        links = pagination_inventory(flow, first.handle)
        if links.ids:
            next_page = follow_next(flow, first.handle, links.ids[0])
```

The inventory returns up to 32 distinct destinations from static `a` and `link` elements with an explicit `next` relation. It uses the captured HTML's effective base URL. Its `ids`, enveloped `content` and `truncated` flag are local results. Control IDs belong to the capture and flow. Forms, scripts, templates, frame content, download links, popup targets, ping URLs and links with event handlers are excluded.

Selection issues one anonymous GET, plus any accepted redirects, through the pinned transport. Every hop must remain HTTPS on the captured host and port, resolve to a public address, and pass the current egress policy. URL user information and fragments are excluded. The subset supports ordinary paths and unique decimal pagination fields named `page`, `p`, `offset`, `start`, `limit` or `per_page`, each with 1–12 digits. URLs are limited to 4,096 characters. Opaque cursors and arbitrary query fields are outside this subset. Browser cookies, script execution and alternate-source recovery are unavailable on this route.

The result is a cleaned, labeled `PageRead` with final URL provenance. A complete `200 text/html` response is required. The transport's 10 MB decoded size and 60-second total limits apply. An eligible direct page receives a new snapshot handle so pagination can continue. Query-bearing pages, redirected responses and other ineligible HTML are call-only. A successful navigation invalidates the previous handle. A rejected request leaves the original capture usable subject to its normal expiry and memory budget.
