"""Conversation-scoped MCP reads for trusted hosts that own the connection."""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp import Client
from mcp.server.mcpserver import MCPServer

from siftfetch.host_flow_tools import register_tools
from siftfetch.host_flow_images import register_images
from siftfetch.research_flow import ResearchFlow


@asynccontextmanager
async def open_host_flow() -> AsyncIterator[Client]:
    """Give one host-created conversation a private, connected MCP client.

    The host opens a separate context for each conversation, including forks
    and delegated workers. It routes calls to the client that it already owns
    and exits the context when that conversation ends.
    """
    with ResearchFlow() as flow:
        server = MCPServer("SiftFetch conversation reads")
        register_tools(server, flow)
        register_images(server, flow)
        async with Client(server, mode="legacy", cache=None) as client:
            yield client
