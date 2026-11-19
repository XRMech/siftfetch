---
topic: snapshot-load
status: verified
last-updated: 2026-11-18
---

# Offline Python snapshot load

This benchmark measures one Python process running 20 or 30 [research flows](library-api.md#public-html-snapshots). Each worker reads a distinct synthetic station page, then requests its full view after the first reads finish. The runner checks each returned reading against the station's evidence, counts fetches, checks the retained payload limit and verifies that closing the flows releases every capture. A handle evicted under memory pressure counts as an unavailable follow-up.

## Reproduce

Run the following commands from the checkout. Each case starts a fresh process so its high-water mark belongs to that scenario.

```powershell
foreach ($pageClass in @('small', 'large')) {
    foreach ($flowCount in @(20, 30)) {
        .venv/Scripts/python.exe -m tools.snapshot_load_benchmark --flows $flowCount --page $pageClass
        if ($LASTEXITCODE -ne 0) { throw "Snapshot benchmark failed" }
    }
}
```

The 8 KiB and 1.25 MiB ASCII pages have the same visible article layout. A synthetic bundled script supplies the extra source bytes. The in-memory HTTP response simulates an explicitly public HTTPS page. A temporary synthetic policy is installed before importing SiftFetch, and a process audit hook rejects socket connects, DNS lookups, binds and datagram sends. Cleaning, labeling, capture admission, eviction, follow-up rendering and cleanup use the production Python implementation.

## Recorded run

Windows, CPython 3.12.8. All four cases fetched each station once and retained zero captures after close. Sizes are MiB, with one MiB equal to 1,048,576 bytes.

| Flows | HTML per flow | Retained payload | Successful follow-ups | Initial process peak | Process peak after workload |
|---:|---|---:|---:|---:|---:|
| 20 | 8 KiB | 0.16 | 20 | 43.17 | 50.81 |
| 30 | 8 KiB | 0.24 | 30 | 43.01 | 52.04 |
| 20 | 1.25 MiB | 25.00 | 20 | 42.89 | 166.33 |
| 30 | 1.25 MiB | 31.25 | 25 | 42.95 | 224.84 |

The 32 MiB process-local payload budget held 25 large pages. Five handles became unavailable before their follow-up reads. Retained payload counts the cache's decoded HTML and URL string allocations after the first reads. Process peak includes Python, worker threads, response generation, native parsers, concurrent rendering and retained data. Allocators can keep memory after a capture is released.

Windows reports peak working set. Linux and macOS report peak resident set size through `getrusage`. Other systems report null for those fields. Peak memory and timings vary with platform and thread scheduling. This short run exercises simultaneous public reads in one process. Real client process counts, idle intervals and the mix of pages require separate measurement before selecting MCP cache defaults.
