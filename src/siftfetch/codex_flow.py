"""Conversation-owned dynamic tools for a trusted Codex app-server client."""
from contextlib import asynccontextmanager

from siftfetch.host_flow import open_host_flow


_NAMESPACE = "siftfetch"


def _failed():
    return {"success": False, "contentItems": [{"type": "inputText", "text": "Flow operation unavailable."}]}


class CodexFlow:
    """Bind once using the host's correlated thread creation/attachment response."""

    def __init__(self, client, tools):
        self._client = client
        self._thread = None
        self._ended = False
        self._properties = {tool["name"]: set(tool["inputSchema"]["properties"]) for tool in tools}
        self.dynamic_tools = [{"type": "namespace", "name": _NAMESPACE,
                               "description": "Read public pages and their evidence.", "tools": tools}]

    def bind(self, thread_result):
        """Accept the result of the host's own start, resume or fork request."""
        if self._ended or self._thread is not None:
            raise RuntimeError("Flow already bound or closed")
        identity = thread_result["thread"]["id"]
        if not isinstance(identity, str) or not identity:
            raise ValueError("Missing app-server thread identity")
        self._thread = identity

    def thread_closed(self, params):
        """Retire this flow immediately on its app-server thread/closed notification."""
        if self._thread is not None and params.get("threadId") == self._thread:
            self._ended = True
            return True
        return False

    async def dispatch(self, params):
        """Handle trusted item/tool/call params. Only arguments originate with the model."""
        if (self._ended or self._thread is None or params.get("threadId") != self._thread
                or params.get("namespace") != _NAMESPACE
                or not all(isinstance(params.get(k), str) and params[k] for k in ("callId", "turnId"))):
            return _failed()
        tool = params.get("tool")
        args = params.get("arguments")
        if (not isinstance(tool, str) or tool not in self._properties or not isinstance(args, dict)
                or not args.keys() <= self._properties[tool]):
            return _failed()
        result = await self._client.call_tool(tool, args)
        if self._ended or result.is_error or any(block.type != "text" for block in result.content):
            return _failed()
        return {"success": True, "contentItems": [{"type": "inputText", "text": block.text}
                                                   for block in result.content]}


@asynccontextmanager
async def open_codex_flow():
    """Create one route on a private app-server connection managed by the host."""
    async with open_host_flow() as client:
        listing = await client.list_tools()
        specs = []
        for tool in listing.tools:
            wire = tool.model_dump(by_alias=True)
            specs.append({"type": "function", "name": wire["name"], "description": wire["description"],
                          "inputSchema": {**wire["inputSchema"], "additionalProperties": False}})
        route = CodexFlow(client, specs)
        try:
            yield route
        finally:
            route._ended = True
