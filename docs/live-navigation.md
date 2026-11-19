---
topic: live-navigation
status: verified
last-updated: 2026-11-18
---

# Live viewport for public Python snapshots

Use `LiveNavigation` to inspect a snapshot in a short-lived headless Chromium browser. Scrolling reads text blocks intersecting the viewport. A native disclosure opens or a uniquely associated ARIA tab panel reveals its local contents. Each action returns the new viewport's text and controls inside an untrusted-content envelope carrying the source URL and inherited page risk. The separate `controls` tuple carries only host-generated IDs and action kinds.

```python
from siftfetch.live_navigation import LiveNavigation

async def read_next_screen(flow, handle):
    async with LiveNavigation(flow, handle) as browser:
        screen = await browser.view()
        for control in screen.controls:
            if control.kind == "next":
                return await browser.select(control.id)
        return screen
```

Pass a live Python `ResearchFlow` and its eligible public capture handle. The optional browser extra, an installed configured Edge or Chrome, and enabled browser reads are required. Each launch consumes a browser read rate slot. Use an async event loop that runs for the lifetime of the viewport. [Python capture rules](library-api.md#public-html-snapshots)

## Navigation and lifecycle

`view()` and `select(id)` return a `Viewport` with `revision`, `content`, `controls`, `captured_at` and `truncated`. Each revision replaces all control IDs. `next` and `previous` scroll 85% of one screen. `details` opens a visible native summary. `tab` reveals an existing hidden tab panel linked by a unique local `aria-controls` reference. Browser events that a site ordinarily uses to load other content are outside these operations.

Use the async context manager or `await browser.close()` for explicit cleanup. The viewer expires after 30 idle seconds or a 120-second lifetime. A watcher checks the owning flow every quarter second to retire an idle viewer after capture eviction, flow release or close. Calls recheck ownership before returning evidence. Unknown or stale IDs raise `KeyError`. Loss of the capture or viewport raises `SnapshotUnavailable`. A browser operation failure closes the viewer.

## Rendering boundary

If cancellation interrupts driver startup, cleanup allows five seconds for readiness. An operating-system spawn still pending at that point keeps the call, event loop, viewport slot and offline proxy alive until its pipe becomes closable or the spawn fails. This OS wait has no fixed deadline. Browser and driver shutdown each have a separate five-second budget once their resources are available.

The renderer uses the existing anonymous capture with its original provenance. It serves sanitized structural HTML and inline CSS from memory in a fresh offline context. The page has no owner cookies. A deny-all proxy, request routing, service-worker blocking, disabled page JavaScript and a restrictive content security policy isolate the browser from network and site-controlled actions. External styles, images, scripts and content loaded later by site code can alter the live site's appearance relative to this view. Callers can select only indexed local controls. Navigation to another URL, forms, downloads, typing and arbitrary scripts are outside the interface.

The process admits two live viewports at a time. Each accepts at most 512,000 UTF-8 input bytes and 8,000 elements. A revision returns at most 30,000 text characters from intersecting text blocks, plus 64 controls with labels of up to 160 characters. Output clipping marks the evidence incomplete. The browser computes layout at 1,000 by 720 CSS pixels. [Static disclosure and tab inspection](snapshot-panels.md)

## Offline acceptance

Run `tests/test_live_navigation.py` with the project test interpreter. Set `SIFTFETCH_BROWSER_TESTS=1` in a browser-equipped test environment to include the native Chromium case. The synthetic station page has a collapsed gauge reading, a local rainfall tab, text below the fold and attempted resource loads directed to a loopback recorder. The test checks each reveal, the guarded capture's fetch count and the empty receiver log. [Offline test rules](testing.md)
