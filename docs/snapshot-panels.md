---
topic: snapshot-panels
status: verified
last-updated: 2026-11-18
---

# Inspect disclosures and tab panels in captured HTML

Use `panel_inventory(flow, handle)` to find native HTML disclosures and explicitly associated ARIA tab panels in an eligible public Python snapshot. Use `read_panel(flow, handle, panel_id)` to inspect one panel. Both calls parse the received HTML locally. They perform zero network requests and execute zero browser actions. [Snapshot eligibility and lifetime](library-api.md#public-html-snapshots)

```python
from siftfetch.panels import panel_inventory, read_panel
from siftfetch.research_flow import ResearchFlow

with ResearchFlow() as flow:
    page = flow.fetch("https://example.com/")
    if page.handle:
        panels = panel_inventory(flow, page.handle)
        if panels.ids:
            result = read_panel(flow, page.handle, panels.ids[0])
```

The inventory returns opaque `ids`, an enveloped `content` string with the kinds and page-supplied labels, and a `truncated` flag. It includes the first 64 supported controls in document order. Labels are limited to 160 characters. A label containing detected hidden text is identified as hidden. Either clipping limit marks the inventory incomplete. The IDs are valid only with the original live capture and flow.

| Received markup | Evidence selected |
|---|---|
| `details`, open or closed | Contents of the selected element, including its first direct `summary` when present |
| `role="tab"` with one `aria-controls` ID | A unique element with that ID and `role="tabpanel"`. If the target supplies `aria-labelledby`, it must include the uniquely identified tab. |
| `role="tab"` without `aria-controls` | One panel whose `aria-labelledby` names that tab's unique ID as its sole reference |

The reader cleans and labels the selected fragment and returns a `PageRead` with the original capture timestamp, handle, clipping flag and inert enveloped content. The page grade is a floor for the selected evidence. The `max_chars` option accepts integers from 1 to 30,000 (default 30,000) before labels and envelope overhead. Clipped evidence is marked incomplete. Invalid, foreign or expired selections raise `KeyError`.

Panel selection never follows `href` or runs event handlers. Content loaded only after a click or scroll cannot appear in the original capture. Live scrolling, pagination and browser interaction remain separate browser-review work.
