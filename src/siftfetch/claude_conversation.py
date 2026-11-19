"""Conversation-private page tools for an embedding Claude Agent SDK host."""
import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from siftfetch.host_flow import open_host_flow


_TOOLS = frozenset({"open_page", "read_page", "page_sizes", "release_page",
                    "page_image_inventory", "read_page_image"})
_PREFIX = "mcp__siftfetch__"


@asynccontextmanager
async def open_claude_conversation(
    approve: Callable[[str, dict], Awaitable[bool]],
) -> AsyncIterator[Callable[[str], Awaitable[str]]]:
    """Yield a text-turn function for one conversation, with host-owned permission prompts."""
    import claude_agent_sdk
    async with _conversation(approve, claude_agent_sdk) as turn:
        yield turn


@asynccontextmanager
async def _conversation(approve, sdk):

    if not callable(approve):
        raise TypeError("A host permission callback is required")
    permitted = {_PREFIX + name for name in _TOOLS}

    async def scope(event, _call_id, _context):
        if event.get("tool_name") not in permitted or event.get("agent_id"):
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": "Outside this conversation's tools"}}
        return {}

    async def permission(name, args, _context):
        if name in permitted and await approve(name, args) is True:
            return sdk.PermissionResultAllow()
        return sdk.PermissionResultDeny(message="Host did not approve the tool call")

    async with open_host_flow() as flow:
        catalog = await flow.list_tools()
        definitions = {item.name: item for item in catalog.tools}
        if not _TOOLS <= definitions.keys():
            raise RuntimeError("Incomplete SiftFetch host tool catalog")

        def bind(name):
            definition = definitions[name]
            @sdk.tool(name, definition.description or name, definition.input_schema)
            async def run(args):
                result = await flow.call_tool(name, args)
                return {"content": [part.model_dump(mode="json", by_alias=True, exclude_none=True)
                                    for part in result.content], "isError": result.is_error}
            return run

        bridge = sdk.create_sdk_mcp_server("siftfetch", tools=[bind(name) for name in sorted(_TOOLS)])
        options = sdk.ClaudeAgentOptions(
            tools=[], disallowed_tools=["Agent", "Task"],
            strict_mcp_config=True, mcp_servers={"siftfetch": bridge},
            permission_mode="default", can_use_tool=permission, verbatim_prompts=True,
            env={"ENABLE_TOOL_SEARCH": "false"},
            hooks={"PreToolUse": [sdk.HookMatcher(hooks=[scope], on_failure="block")]},
            extra_args={"no-session-persistence": None, "permission-prompts": "host"})
        async with sdk.ClaudeSDKClient(options=options) as client:
            lock = asyncio.Lock()
            usable = True
            closed = False

            async def turn(text: str) -> str:
                nonlocal usable
                if not isinstance(text, str):
                    raise TypeError("Supply one text prompt")
                async with lock:
                    if closed or not usable:
                        raise RuntimeError("Conversation unavailable")
                    usable = False
                    await client.query(text)
                    async for message in client.receive_response():
                        if isinstance(message, sdk.ResultMessage) and not message.is_error:
                            usable = True
                            return message.result or ""
                    raise RuntimeError("Claude did not complete the turn")
            try:
                yield turn
            finally:
                closed = True
