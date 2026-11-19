"""Tools registered only on an individually owned, host-created MCP endpoint."""
from functools import partial
from typing import Annotated, Literal

import anyio
import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from siftfetch import tools
from siftfetch.research_flow import PageRead, ResearchFlow, SnapshotUnavailable


_InitialView = Literal["auto", "readability", "full", "raw"]
_View = Literal["auto", "readability", "full", "raw", "source"]
_Chars = Annotated[int, Field(strict=True, ge=1, le=30000)]
_Handle = Annotated[str, Field(min_length=1, max_length=128)]


def _page(read: PageRead) -> dict:
    return {"status": "ok" if read.handle else "call_only", "handle": read.handle,
            "captured_at": read.captured_at, "content": read.content,
            "size_bytes": read.size_bytes, "truncated": read.truncated}


def register_tools(server: MCPServer, flow: ResearchFlow) -> None:
    """Bind the four tools to the flow exclusively owned by this endpoint."""
    @server.tool()
    async def open_page(url: str, view: _InitialView = "auto") -> dict:
        """Fetch with normal outbound checks. Each successful read replaces any prior capture."""
        try:
            result = await anyio.to_thread.run_sync(
                tools.guarded, partial(flow.fetch, url, extract=view), "Fetch")
        except httpx.HTTPStatusError as exc:
            return {"status": "http_error", "content": tools._http_failure(exc, "Fetch")}
        if isinstance(result, str):
            return {"status": "network_error", "content": result}
        return _page(result)

    @server.tool()
    async def read_page(handle: _Handle, view: _View = "auto", max_chars: _Chars = 30000) -> dict:
        """Read a bounded, labeled view of this endpoint's capture without making a request."""
        try:
            page = await anyio.to_thread.run_sync(partial(flow.read, handle, extract=view,
                                                        max_chars=max_chars))
        except SnapshotUnavailable:
            return {"status": "unavailable"}
        return _page(page)

    @server.tool()
    async def page_sizes(handle: _Handle, max_chars: _Chars = 30000) -> dict:
        """Measure each bounded view in UTF-8 bytes including its untrusted-content markings."""
        try:
            sizes = await anyio.to_thread.run_sync(partial(flow.view_sizes, handle, max_chars=max_chars))
        except SnapshotUnavailable:
            return {"status": "unavailable"}
        return {"status": "ok", "sizes": sizes}

    @server.tool()
    async def release_page(handle: _Handle) -> dict:
        """Discard this endpoint's matching capture. Repeated releases have the same result."""
        await anyio.to_thread.run_sync(flow.release_if_current, handle)
        return {"status": "released"}
