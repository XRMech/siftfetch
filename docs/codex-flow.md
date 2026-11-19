---
topic: Codex app-server conversation adapter
status: verified
last-updated: 2026-11-19
---

# Connect one Codex thread to a private SiftFetch flow

A Python application running its own Codex app-server client can register
SiftFetch as namespaced dynamic tools. Codex supplies the thread identity on
its server-to-client call. Only the nested `arguments` are model arguments.
The adapter rejects other thread IDs, namespaces, tools and unexpected
arguments. Only expose its generated dynamic tools to the model.

Open one context per thread on a **trusted, host-owned connection**. Keep
the binding on that connection's dispatcher. A thread ID does not authenticate
traffic across sockets or from another caller. Do not accept routing params
submitted by an agent, a webhook, or another app-server connection.
Run the host's normal tool authorization and approval checks before dispatch.
Return the result on the original JSON-RPC request ID. Its `success` boolean
and `contentItems` array carry the status and labeled `inputText` output.

The following example uses a dedicated single-thread dispatcher. `rpc` is the host's existing app-server client, and `authorize` is its ordinary tool permission handler. It assumes initialization with `capabilities.experimentalApi = true`. The event reader continues processing close notifications during tool calls.

```python
from siftfetch.codex_flow import open_codex_flow
import anyio

async def run_thread(rpc, authorize):
    async with open_codex_flow() as route:
        created = await rpc.request("thread/start", {"dynamicTools": route.dynamic_tools})
        route.bind(created)

        async def handle_call(event):
            params = event["params"]
            result = {"success": False, "contentItems": []}
            if params.get("threadId") == created["thread"]["id"] and await authorize(params):
                result = await route.dispatch(params)
            await rpc.respond(event["id"], result)

        async with anyio.create_task_group() as calls:
            try:
                # The host starts turns using created["thread"]["id"].
                async for event in rpc.events():
                    if event["method"] == "thread/closed" and route.thread_closed(event["params"]):
                        break
                    if event["method"] == "item/tool/call":
                        calls.start_soon(handle_call, event)
            finally:
                calls.cancel_scope.cancel()
```

The host must correlate the start response to its own pending request.
Route by the authenticated connection and bound thread before delivering
tool calls. Use a new context for each fork, child, or resumed thread that
needs these tools. Unknown threads receive no capture access. Dynamic tool
definitions restored by Codex on resume do not restore a SiftFetch capture.

The host must exit the context at thread end, cancellation, or connection
loss. On receipt of the matching close notification call `thread_closed`
immediately, then arrange context exit in the owning task. The close signal
prevents an in-flight result completing afterward from returning evidence.
Keep outgoing JSON-RPC responses tied to their original request and
connection. Never forward a queued result to a replacement connection.

The local protocol check used Codex CLI 0.170.0 and an isolated ephemeral
thread. A scripted loopback Responses service caused the real app-server to
emit a dynamic `read_page` call. The server accepted the stale-handle
response and completed its turn. A separate offline test opens a synthetic
page, reads another view from that capture and checks foreign-thread denial
and close behavior. These results concern a custom app-server client.
Stock MCP setups keep their existing single-call behavior.

See [private flow eligibility and lifetime](host-flow.md).
