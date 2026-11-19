---
topic: host-flow
status: verified
last-updated: 2026-11-19
---

# Reuse a public page across MCP calls in a Python host

A host that controls conversation creation and tool dispatch can open a private MCP client with `siftfetch.host_flow.open_host_flow()`. Keep the context open across turns for that conversation. Create a fresh context for every independent conversation, fork and delegated agent. Bind the dispatch route in trusted host code before delivering any model-supplied arguments, and apply the host's ordinary tool permission checks at that boundary. Sharing the client object gives its recipient access to that flow.

```python
import json
from siftfetch.host_flow import open_host_flow

async def read_reference(url):
    async with open_host_flow() as client:
        first = await client.call_tool("open_page", {"url": url})
        if first.is_error:
            raise RuntimeError("Page open failed")
        page = json.loads(first.content[0].text)
        if not page.get("handle"):
            return page
        result = await client.call_tool(
            "read_page", {"handle": page["handle"], "view": "full"}
        )
        if result.is_error:
            raise RuntimeError("Page read failed")
        return json.loads(result.content[0].text)
```

| Tool | Purpose |
|---|---|
| `open_page` | Fetch a page through the outbound checks and return a marked first read. Only eligible public HTML receives a handle. |
| `read_page` | Render another view from that capture, including inert decoded HTML with `view="source"`. |
| `page_sizes` | Measure the enveloped views in UTF-8 bytes without fetching the page again. |
| `page_image_inventory` | List capture-local image IDs and marked labels without fetching pixels. |
| `read_page_image` | Use the page handle, one listed image ID and `operation="ocr"` or `"describe"` to fetch that image through the guarded transport. See [local backends](mcp-images.md). |
| `release_page` | Release the supplied handle in the current flow. A stale or foreign handle leaves the current capture available. |

The initial read uses a 30,000-character presentation limit. Both `read_page` and `page_sizes` accept `max_chars` from 1 to 30,000. A read of an unknown, expired or released handle returns `unavailable`. Close the context when its conversation ends, disconnects or is cancelled. On resume after closure, create a fresh context and open a new page. The existing [capture eligibility, size and idle limits](snapshots.md) apply across flows in the process. Pages can be evicted under memory pressure. A caller can choose to start a new acquisition when a capture is unavailable.

For a Codex app-server client, the [dynamic tool adapter](codex-flow.md) binds this connection to the thread returned by the host. A host using the [Claude Agent SDK controller](claude-conversation.md) can supply a private flow per conversation with ordinary host permission checks. The standard Claude Code and Codex stdio registrations use the [single-call reading tools](mcp-tools.md). In the measured Claude Code delegation configuration, a parent and child shared a server process. That registration cannot assign a separate flow from process identity. [Host isolation checks](mcp-isolation-probe.md)
