---
topic: site-cases
status: verified
last-updated: 2026-11-18
---

# Local site lists

Two independent owner settings enable persistent review lists. Both default to `off`. Each list keeps its records until the owner removes them. Turning a switch off stops new entries and preserves the existing register.

| Setting | What qualifies |
|---|---|
| `failed_sites` | An anonymous page read encounters a terminal HTTP or network error, an unrecovered bot wall, or insufficient content after alternate-source recovery. A Python host can also call `flow.report_missing_evidence(handle)` once per eligible capture when a successful read omitted evidence. |
| `case_study_sites` | An eligible direct anonymous public read produces a complete medium, high-candidate or high grade with a recognized detector category. The register retains one category per observation, preferring hidden evidence. Repeated reads can increment the count for a page. |

Use the site lists to find examples for review. A site aggregate can reflect one page fetched multiple times. An HTTP error can be specific to one URL. Grade and repetition alone cannot establish malicious intent. Keep manual observations linked to the original field record and record a separate conclusion after review.

To enable both lists, set `"failed_sites": "on"` and `"case_study_sites": "on"` in the owner's existing [configuration](configuration.md). Automatic failures require transport evidence of a direct anonymous request to a verified public address. They exclude pre-verification DNS failures, redirects, browser attempts, query-bearing requests, and authentication or private-cache responses. Policy denials and successful recoveries do not count as failed pulls. The explicit report requires a live eligible Python snapshot and increments only after storage succeeds.

The fixed data file is `site-cases.sqlite3` in the [data folder](setup/data-folder.md). Rows contain the UTC day, registrable site, event kind, fixed reason, detector grade and revision where applicable, and count. These aggregate rows omit page paths and excerpts. The separate evidence records retain checked source paths, bounded passages and observation times. See [research cases](research-cases.md) and [manual candidate reporting](reported-candidates.md). IP addresses, unknown suffixes, private-suffix tenants and configured local or login origins are excluded. Site minimization requires a successful local protected-value check. SQLite transactions serialize increments across processes. There is no automatic purge, rotation, export, or upload.

## Review

These commands read local data and print JSON. `--since` includes the specified UTC date. Omit it for the entire retained history.

```powershell
python -m siftfetch.site_cases failure
python -m siftfetch.site_cases candidate --since 2026-10-28
```

Detailed [sightings](sightings.md) keep their existing bounded retention and separate switch. The persistent lists start when enabled. They do not backfill past observations. Anonymous [view usage counts](view-usage.md) remain independent of both settings.
