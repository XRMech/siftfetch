---
topic: parameters
status: verified
last-updated: 2026-10-27
---

# Parameters
Defaults preserve anonymous, unattended fetching. Every redirect is checked before connection. A block never authorizes rerouting a protected value.

| Parameter | Default | Meaning |
|---|---|---|
| url | required | HTTP(S) destination |
| browser | none | edge/chrome loads cookies only for approved origins |
| max_chars | 30000 fetch; 0 save | Output cap; 0 removes presentation cap |
| offset | 0 | Resume character offset |
| mode | content | outline produces a heading map |
| section | None | Exact/unique partial heading; takes precedence over offset |
| extract | auto | Layout-aware; readability/full/raw select broader content |
| show_browser | false | Visible read; browser mode must be enabled |
| session_kind | unattended | Explicit library attendance |
| spotlight | config paragraph | paragraph/words/off |
| query | required | Search query checked before DDGS |
| max_results | 5 | Clamped to 1-20 |
| name | required | Sanitized relative save name; .md appended |
| overwrite | false | Replace existing saved page |
| expect | required | pdf/html/text/json/xml/zip |
| max_bytes | MCP 50000000 | Download cap; caller can lower only |
| staging_dir | None | Library download root override |
| kind | None | Substitute field or session attendance |
| text, raw | required text; empty raw | Clean text and raw body for hidden inspection |
| tool, complete | label; true | Sighting source; false forces high risk |
| call, operation, exc | required | Callable, operation label and exception |

## Extraction limits
`raw` still removes scripts, styles, iframes and SVG; it is not page source. `source` is unsupported. Extraction cannot recover HTML absent from the response. Alternate-source recovery remains policy checked. Transport caps are 10 MB decoded/60 seconds, browser HTML 15 MB, download 50 MB/120 seconds. DNS can add its system timeout.
