---
topic: mcp-tools
status: verified
last-updated: 2026-10-28
---

# MCP tools
Run `python -I -m siftfetch.server` over stdio. MCP delegates to the same library policy. Hosted tools outside this server do not inherit protection. Defaults are unattended.

| Tool | Parameters (defaults) | Returns |
|---|---|---|
| fetch_url | url; browser=none, max_chars=30000, offset=0, mode=content, section=None, extract=auto, show_browser=false, spotlight=None | Enveloped Markdown |
| search_web | query; max_results=5 | Labeled title/URL/snippet records |
| fetch_and_save | url, name; browser=none, overwrite=false | Save/existing/quarantine record |
| download_to_staging | url, expect; max_bytes=50000000 | Download/quarantine metadata |
| list_sessions | none | Browser login availability, no cookie-store read |
| policy_status | none | Read-only redacted status dictionary; never raises |
| get_substitute | kind=None | Approved identity fields; missing fields omitted |

See [parameters](api/parameters.md) and [results](api/results.md) for fields, envelope, risk grades and markers. Async tools move blocking work to worker threads.

Cleaned HTML includes `[ATTRIBUTE element.name] value [END ATTRIBUTE]` entries before body prose, bounded to 32,768 value characters. They expose alt/title, accessibility labels, placeholders, data attributes, metadata, SVG title/description and JSON script text fields. Values remain untrusted text; these labels are not authority. Risk depends on content. Hidden titles stay within hidden-region markers instead of repeating as link titles. The envelope and grade fields are unchanged.

## Errors and safety
Network failures become a network_error string. Policy denials, invalid options and non-timeout download rejections become MCP tool errors. get_substitute fails with policy_unavailable for unsafe substitutes; unknown kind raises ValueError. After a block, retrieve the named substitute rather than identifiers.

Disabling egress skips value checks, while fetch/clean/label/spotlight and independent sightings continue. Every envelope says `SiftFetch egress protection is disabled`. Domain blocks, private-address checks and file protections remain.

DDGS checks the query before search but controls its own engine connections outside the pinned transport. Search may return a blocked-domain URL as evidence. Following it through fetch_url checks its destination and every redirect.

## Redacted policy status
policy_status returns loaded/error, effective protection and disabling causes, selected formats and shadow warnings, identifier totals by kind/class and public_search count, and exception counts by operation (active/expired/invalid; unrecognized operations grouped as other). It includes safe config settings, collection counts, substitute kinds, download_dir set/unset, and valid contact_alias set/unset with config/env source; invalid aliases are omitted. Environment entries show set/unset only, except SIFTFETCH_ENABLED may show 0/1. Data/download paths expose exists/writable booleans; absent directories use the nearest existing parent for writability. No labels, identities, origins, prefixes, aliases or path strings appear. Policy errors return loaded=false with file/field text; unexpected errors use a generic message. No files are created.
