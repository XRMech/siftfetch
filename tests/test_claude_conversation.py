"""Controller contract using an injected fake SDK. No agent or model SDK is loaded."""
from types import SimpleNamespace

import anyio
import pytest

from siftfetch import claude_conversation as controller


class FakeResult:
    is_error = False
    result = "Synthesized answer"


class FakeClient:
    def __init__(self, options):
        self.options = options
        self.sent = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass

    async def query(self, text):
        self.sent.append(text)

    async def receive_response(self):
        yield FakeResult()


def test_private_controller_tool_scope_permissions_and_text_only_turns():
    clients = []
    def client_factory(*, options):
        client = FakeClient(options)
        clients.append(client)
        return client

    sdk = SimpleNamespace(ClaudeAgentOptions=SimpleNamespace, ClaudeSDKClient=client_factory,
                          HookMatcher=SimpleNamespace, ResultMessage=FakeResult,
                          create_sdk_mcp_server=lambda name, tools: tools,
                          tool=lambda name, description, schema: lambda handler: (name, handler),
                          PermissionResultDeny=lambda **_: False, PermissionResultAllow=lambda: True)
    prompts = []
    async def approve(name, args):
        prompts.append(name)
        return False

    async def scenario():
        async with controller._conversation(approve, sdk) as turn:
            opts = clients[0].options
            assert opts.tools == [] and opts.disallowed_tools == ["Agent", "Task"]
            assert opts.strict_mcp_config and opts.verbatim_prompts and opts.permission_mode == "default"
            assert not hasattr(opts, "allowed_tools") and opts.env == {"ENABLE_TOOL_SEARCH": "false"}
            assert set(opts.mcp_servers) == {"siftfetch"}
            assert set(dict(opts.mcp_servers["siftfetch"])) == {
                "open_page", "page_sizes", "read_page", "release_page", "page_image_inventory", "read_page_image"}
            matcher, = opts.hooks["PreToolUse"]
            assert matcher.on_failure == "block"
            gate, = matcher.hooks
            page = "mcp__siftfetch__read_page"
            for name, agent in (("Agent", None), ("Bash", None), ("Task", None), (page, "synthetic-child")):
                decision = await gate({"tool_name": name, "agent_id": agent}, None, None)
                assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
            assert await gate({"tool_name": page}, None, None) == {}
            assert await opts.can_use_tool("Agent", {}, None) is False and not prompts
            assert await opts.can_use_tool(page, {}, None) is False and prompts == [page]
            with pytest.raises(TypeError):
                await turn({"resume": "other"})
            assert await turn("Synthetic question") == "Synthesized answer"
            assert clients[0].sent == ["Synthetic question"]
        with pytest.raises(RuntimeError, match="unavailable"):
            await turn("Later")
    anyio.run(scenario)
