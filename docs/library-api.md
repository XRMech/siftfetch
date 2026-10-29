---
topic: library-api
status: verified
last-updated: 2026-10-28
---

# Library API
Use labeled/enveloped output for model context. Never expose `fetch_url_raw` output directly. This library imports no MCP SDK; errors raise unless wrapped with `guarded`.

## Public functions
Import from `siftfetch.tools`. Existing positional parameters and return shapes remain supported. Calls are synchronous and blocking; async hosts should use worker threads. Policy cache access is locked; do not mutate process environment concurrently.

| Function signature | Result |
|---|---|
| `policy_status()` | Redacted policy status dictionary; never raises; also available as egress_policy.policy_status() |
| `tighten(changes)` | Config delta dictionary; returns JSON-compatible `{ok, changed_files, message}`; no values echoed |
| `session_kind()` | attended only with explicit opt-in; otherwise unattended |
| `fetch_url_raw(url, browser="none", max_chars=30000, offset=0, mode="content", section=None, extract="auto", show_browser=False, session_kind="unattended")` | `(markdown, raw_body)`, unlabeled |
| `label(text, raw="", *, url="", tool="label", complete=True, spotlight=None)` | `(labeled_text, Scan)`; records sightings |
| `scan_record(scan)` | Grade metadata dictionary |
| `fetch_url_sync(url, browser="none", max_chars=30000, offset=0, mode="content", section=None, extract="auto", show_browser=False, session_kind="unattended", spotlight=None)` | Enveloped Markdown string |
| `search_web_sync(query, max_results=5)` | List of labeled result dictionaries |
| `fetch_and_save_sync(url, name, browser="none", overwrite=False, max_chars=0, session_kind="unattended")` | Save/existing/quarantine dictionary |
| `download_sync(url, expect, max_bytes, staging_dir=None)` | Download/quarantine metadata; root override supported |
| `list_sessions_sync(kind=None)` | Browser login availability; never opens cookie stores |
| `get_substitute(kind=None)` | Approved fields dictionary; absent fields omitted |
| `network_failure(exc, operation, url="")` | One-line network_error string |
| `guarded(call, operation, url="")` | Call result or network-error string |

See [parameters](api/parameters.md) and [result shapes](api/results.md). `EgressDenied` carries `.decision`; `guarded` preserves policy denials and non-timeout `DownloadRejected` errors. Save failures raise `SaveError`; invalid options may raise `ValueError`; fetch budgets raise `FetchBudgetExceeded`. HTTP status errors remain HTTP exceptions.

## Minimal host
`tighten({"guard_lock": true})` in JSON terms enables the lock; in Python use `True`. Allowed changes enable value checks/guard lock, retain or add lock paths/blocked domains, move secret_file_mode toward strict, or turn browser_fetch.mode off. Lists are complete replacement lists and must retain existing members. Nested dictionaries merge. All other changes, malformed baselines and mixed plans return ok=false with editor guidance. Aliases/substitutes never enter this API. No MCP tightening tool is registered. `policy_status()` retains its existing shape.

Install normally, or use `--no-deps` only when the host supplies the declared HTML/search/HTTP dependencies. MCP version conflicts need not affect library imports. Configure policy through [owner setup](setup/policy-files.md), never by copying protected values into application code.

```python
from siftfetch import tools
from siftfetch.egress_policy import EgressDenied

url = "https://example.com/"
try:
    page = tools.guarded(lambda: tools.fetch_url_sync(url), "Fetch", url)
except EgressDenied as exc:
    page = exc.decision.message()
```

## Existing helper exports
`siftfetch.benchmark.run(corpus_dir=None) -> dict` is a public offline measurement API. It uses checkout fixtures by default or a local corpus directory, reads no owner policy and writes no sightings. It returns patterns_version, corpus_hash, metrics and per-case results; malformed inputs raise ValueError, KeyError or TypeError, and unavailable files raise OSError. See [benchmark schema and metrics](benchmark.md).

The module also imports `fetch`, `bot_wall`, `list_available_sessions`, `clean_html`, `alternate_source_urls`, `site_api_urls`, `api_payload_to_markdown`, `json_to_markdown`, `present_markdown`, and dataclass `replace`. Existing imports remain available; prefer defining modules for new integrations. Fetch returns an HTTP response, cleaning helpers strings, URL helpers lists, and bot_wall a boolean. Helpers do not replace labeling and enveloping.

See [policy API](api/policy.md) for matching/scan primitives. Disabling egress skips value checks only; cleaning, labels, spotlight, file protections, destination checks and independent sightings continue.
