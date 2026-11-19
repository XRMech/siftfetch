---
topic: read-only navigation in MCP
status: verified
last-updated: 2026-11-18
---

# Read-only navigation in MCP

`navigate_page(url, mode, selections=None, expected_next_url=None)` opens a fresh anonymous page for each call. Supply a public HTTPS URL. Page text, destinations and labels appear inside the standard untrusted-content envelope. The tool releases its capture and any browser before returning.

| Mode | Without selections | With selections |
| --- | --- | --- |
| `panels` | List native disclosures and supported local tab panels in document order. | Read up to four distinct numbered panels from that capture. |
| `next` | List declared same-origin next-page destinations. | Follow one numbered link. Supply the full destination from the inventory as `expected_next_url`. A changed destination stops the request. Each redirect undergoes the pagination and outbound checks. |
| `viewport` | Read the initial viewport and its available controls. Requires browser reads enabled. | Apply up to four numbered controls in sequence. Each selection uses the inventory produced by the preceding action. Return the final viewport. |

Count controls from one in the order shown. The tool accepts ordinals up to 64 for panels and viewport controls, and 32 for pagination. Ordinals refer to the current fetch. Pages can change between calls. The viewport renders an offline, sanitized copy with browser network access denied. Browser control IDs in the evidence apply only within that viewport revision.

When the initial response cannot be retained, `call_only` returns the first marked read. If the capture expires or is evicted during navigation, `capture_unavailable` returns that read. The tool accepts no persistent handle.
