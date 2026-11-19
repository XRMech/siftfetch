"""Synthetic stdio probe for observing how an MCP host shares server processes."""
from contextlib import asynccontextmanager
from importlib.metadata import version
import secrets
import sys
from typing import Literal

from mcp.server.mcpserver import Context, MCPServer


def create_probe():
    instance = secrets.token_hex(16)
    handle = None
    edition = 0

    @asynccontextmanager
    async def lifespan(server):
        nonlocal handle
        print(f"isolation-probe started {instance}", file=sys.stderr, flush=True)
        try:
            yield {}
        finally:
            handle = None
            print(f"isolation-probe stopped {instance}", file=sys.stderr, flush=True)

    probe = MCPServer("Synthetic flow isolation probe", lifespan=lifespan)

    @probe.tool()
    async def probe_instance(ctx: Context) -> dict:
        """Identify this synthetic server instance and the current MCP protocol."""
        return {"instance": instance, "sdk": version("mcp"),
                "protocol": ctx.request_context.protocol_version}

    @probe.tool()
    async def probe_open() -> dict:
        """Replace the one synthetic capture in this process and return its handle."""
        nonlocal handle, edition
        edition += 1
        handle = secrets.token_hex(16)
        return {"instance": instance, "handle": handle, "edition": edition}

    @probe.tool()
    async def probe_access(ticket: str, operation: Literal["read", "size", "release"]) -> dict:
        """Test the supplied synthetic handle against this instance's one slot."""
        nonlocal handle
        if ticket != handle:
            return {"instance": instance, "status": "unavailable"}
        result = {"instance": instance, "status": "available"}
        content = f"Synthetic capture {edition}"
        if operation == "read":
            result["content"] = content
        elif operation == "size":
            result["size_bytes"] = len(content.encode("utf-8"))
        else:
            handle = None
            result["status"] = "released"
        return result

    return probe


if __name__ == "__main__":
    create_probe().run(transport="stdio")
