---
topic: mcp-tools
status: verified
last-updated: 2026-11-18
---

# MCP tools
Run `python -I -m siftfetch.server` over stdio. MCP delegates to the same library policy. Hosted tools outside this server do not inherit protection. Defaults are unattended.

A Python host that owns conversation dispatch can use a [private MCP flow](host-flow.md) to reuse one capture across calls.

| Tool | Parameters (defaults) | Returns |
|---|---|---|
| fetch_url | url; browser=none, max_chars=30000, offset=0, mode=content, section=None, extract=auto, show_browser=false, spotlight=None | Enveloped Markdown |
| fetch_page_views | url, views (default `["auto"]`), include_sizes=false | Selected views of one public capture, with optional UTF-8 byte counts |
| fetch_page_images | url, operation=inventory, image_number=None, expected_inventory=None | List static images or return local OCR or a description of one selected image. [Image selection and backends](mcp-images.md) |
| navigate_page | url, mode, selections=None, expected_next_url=None | Inspect panels, use the bounded offline viewport or follow a reviewed next-page link. [Navigation options](mcp-navigation.md) |
| search_web | query; max_results=5 | Labeled title/URL/snippet records |
| fetch_and_save | url, name; browser=none, overwrite=false | Save/existing/quarantine record |
| download_to_staging | url, expect; max_bytes=50000000 | Download/quarantine metadata |
| list_sessions | none | Browser login availability, no cookie-store read |
| policy_status | none | Read-only redacted status dictionary; never raises |
| get_substitute | kind=None | Approved identity fields; missing fields omitted |

See [parameters](api/parameters.md) and [results](api/results.md) for fields, envelope, risk grades and markers. Async tools move blocking work to worker threads.

Cleaned HTML marks alt/title, accessibility labels, placeholders, data attributes, metadata, SVG titles/descriptions and JSON script text with `[ATTRIBUTE element.name] value [END ATTRIBUTE]`. The inventory precedes body prose through 4,096 rendered characters. Larger inventories follow the article and receive a separate scan. More than 32,768 value characters yields an incomplete, high-risk grade. Values remain untrusted. Hidden titles stay inside hidden-region markers.

## Multiple reading views

Call `fetch_page_views` with up to five distinct choices from `auto`, `readability`, `full`, `raw` and `source`. Source includes decoded HTML as inert, labeled text. Each view uses a 30,000-character presentation limit. Size counts include its full untrusted-content envelope. For sizes alone, pass `views=[]` and `include_sizes=true`.

The result contains `status`, `captured_at` (UTC or null), and `views`, keyed by view name. Each entry carries `content`, `size_bytes` and `truncated`. Requesting `include_sizes` adds a `sizes` dictionary. For an eligible capture, `status=ok` and the size catalog covers every view. If the page is ineligible (`call_only`) or evicted during rendering (`capture_unavailable`), the tool returns the first available cleaned read and any completed views. Size-only requests keep `views` empty. A request for source alone falls back to `auto` in these cases.

The tool releases its flow before returning. A new call fetches again. The generic MCP input hook may ask or deny before the guarded transport checks the URL and redirects. Capture eligibility follows the [Python snapshot rules](library-api.md#public-html-snapshots).

## Errors and safety
Network failures become a network_error string. HTTP error statuses become an http_error string with the code and its standard name, such as `Fetch failed (http_error): HTTP 404 Not Found.`; the server's reason text is never shown. Policy denials, invalid options and non-timeout download rejections become MCP tool errors. get_substitute fails with policy_unavailable for unsafe substitutes; unknown kind raises ValueError. After a block, retrieve the named substitute rather than identifiers.

Disabling egress skips value checks, while fetch/clean/label/spotlight and independent sightings continue. Every envelope says `SiftFetch egress protection is disabled`. Domain blocks, private-address checks and file protections remain.

DDGS checks the query before search but controls its own engine connections outside the pinned transport. Search may return a blocked-domain URL as evidence. Following it through fetch_url checks its destination and every redirect.

## Redacted policy status
policy_status returns loaded/error, effective protection and disabling causes, selected formats and shadow warnings, identifier totals by kind/class and public_search count, and exception counts by operation (active/expired/invalid; unrecognized operations grouped as other). It includes safe config settings, collection counts, substitute kinds, download_dir set/unset, and valid contact_alias set/unset with config/env source; invalid aliases are omitted. Environment entries show set/unset only, except SIFTFETCH_ENABLED may show 0/1. Data/download paths expose exists/writable booleans; absent directories use the nearest existing parent for writability. No labels, identities, origins, prefixes, aliases or path strings appear. Policy errors return loaded=false with file/field text; unexpected errors use a generic message. No files are created.
