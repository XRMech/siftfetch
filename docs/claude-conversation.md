---
topic: Claude Agent SDK conversation-private page reads
status: verified
last-updated: 2026-11-19
---

# Claude Agent SDK conversation-private page reads

A trusted Python host can give one Claude conversation its own SiftFetch capture. Install the optional `siftfetch[claude]` extra. Start from the host's trusted working directory with its existing Claude permissions, hooks and authentication. The host owns the lifetime of each conversation and opens a separate context for every delegated worker.

```python
from siftfetch.claude_conversation import open_claude_conversation

async def research(question, ask_user):
    async with open_claude_conversation(approve=ask_user) as turn:
        answer = await turn(question)
        follow_up = await turn("Check the original table for the units.")
        return answer, follow_up
```

`ask_user(tool_name, arguments)` is an asynchronous host permission dialog. When Claude requests a decision, return `True` only when the host approves that specific request. A false decision denies it. The controller leaves ordinary Claude permission checks active and adds a fail-closed pre-tool check for its tool names and top-level conversation. The host must trust its own settings and hooks.

| Available tools | Behavior |
| --- | --- |
| `open_page`, `read_page`, `page_sizes`, `release_page` | Fetch eligible public pages, read another view, measure and release the current capture. |
| `page_image_inventory`, `read_page_image` | Inspect supported images and request selected evidence under the same capture and privacy settings. |

Each context accepts text turns in sequence. Claude uses its normal model connection, so returned tool evidence becomes model input. Page evidence retains its untrusted-content markings. The controller fixes the SDK tool catalog, disables built-in delegation and tool search, and delivers prompts verbatim. Exiting the context closes the private MCP flow. A fresh context is required after a failed turn.

The verified combination uses Claude Agent SDK 0.2.185 with its bundled Claude Code 2.1.328. The separate manual acceptance used two controllers, disposable credentials and a local model responder. Each received a distinct handle, the parent still read its own capture after the sibling closed, and a denied read returned no evidence. All six SiftFetch tools were present in the model request. See the [host isolation checks](mcp-isolation-probe.md).
