---
topic: changelog
status: verified
last-updated: 2026-11-19
---

# Changelog
Every release records its changes here. Before 1.0, compatibility changes are listed explicitly; security fixes name the affected versions.

## Unreleased

- Compare the size and retained evidence of four extraction views with the [offline benchmark](docs/extraction-benchmark.md).
- Reuse anonymous public HTML within a [Python research flow](docs/snapshots.md). MCP callers can request multiple views, image evidence and read-only navigation through [single-call tools](docs/mcp-tools.md).
- Python hosts can bind [a private MCP client](docs/host-flow.md) to each conversation for cross-call reads and explicit capture release.
- Opt in to [richer-view counters](docs/view-usage.md) and [local site records](docs/site-cases.md), including dated potential-injection excerpts and reviewer classifications.
- Shortened views retain known page warnings. Research observations preserve available capture times and exclude locally generated section diagnostics.
- Failed image reads return a status-only HTTP error. Checked requests suppress HTTPX request-line logs containing full URLs. Offline browser cleanup waits for teardown during cancellation.

## 0.1.0
First public release. Early: detection is heuristic and model resistance is not yet measured; see the [threat model](docs/threat-model.md).

### Cleaning incoming content
- Hidden-text detection: CSS display and visibility, opacity, off-screen and clipped boxes, zero-size elements, transparent or background-colored text, tiny fonts, `aria-hidden`, comments, `noscript`, zero-width and control characters.
- Injection scanning with known patterns and reader-directed signals, graded none, low, medium, high-candidate or high.
- Spotlighting, flagged spans and untrusted-content envelopes on every result; instructions in dropped boilerplate raise risk without being shown.
- PDF text extraction with the optional `pdf` extra; binary bodies return a notice instead of decoded bytes.
- Risky saves and downloads go to quarantine; a local sightings log records detections.

### Outbound protection
- Listed identifiers and credentials are checked in URLs, headers and queries, through padding and common encodings.
- Domain blocklist, DNS pinning, checked redirects, and size and time budgets.

### Agent integration
- MCP server tools: `fetch_url`, `search_web`, `fetch_and_save`, `download_to_staging`, `list_sessions`, `get_substitute`, `policy_status`.
- Hook for Claude Code and Codex: denies built-in web tools that skip cleaning, reroutes literal shell fetches through `siftfetch get`, and guards policy and dotenv reads.
- Python library in `siftfetch.tools`, usable without the MCP SDK.
- `siftfetch` command: `setup` wizard with Standard, Lockdown and Custom presets, `init`, `install` with `--adopt` for existing setups, `doctor`, `configure`, `tighten`, `uninstall` and `get`.
- Optional Lockdown: guard lock on SiftFetch's own settings, strict secret-file checks, browser fetch off.

### Quality
- Offline test suite and a clean-room install check, run in CI on Windows, macOS and Linux with Python 3.11 to 3.13.
- Packaged benchmark: `siftfetch benchmark` measures detection and false positives on a bundled corpus of 113 cases.
