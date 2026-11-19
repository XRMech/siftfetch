---
topic: reported-candidates
status: verified
last-updated: 2026-11-18
---

# Report an observed passage for research

With `case_study_sites` enabled, a Python host can flag a passage from a public snapshot for later local review, including a passage the scanner graded `none` or `low`. A reporter observation means that someone selected the passage for study. Its review status and the scanner's grade remain separate.

```python
def report_selected_passage(flow, page, selected_text):
    """Called after a reviewer selects a passage from this captured page."""
    if page.handle is None:
        return False
    return flow.report_candidate(page.handle, selected_text)
```

`flow.report_candidate(handle, excerpt)` accepts 1–500 characters containing some non-whitespace text. Verification looks for an exact contiguous match in the captured HTML or its default cleaned view with the presentation cap, metadata block and link inventory disabled. The check runs locally and makes zero requests. A mismatch or invalid length raises `ValueError`. A foreign, expired, released or replaced handle raises `SnapshotUnavailable`.

A successful write returns `True`. A second report of the same passage from that capture returns `False`. The flow retains only a digest for each successfully reported passage and admits up to 32 distinct reports per capture. Disabled recording, a suppressed report, the per-capture limit or unavailable storage also yields `False`. The persistent archive applies its own source and excerpt checks. [Local case-study settings and review](site-cases.md) · [Python snapshot rules](library-api.md#public-html-snapshots)
