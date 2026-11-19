"""Read static images from the capture owned by one private host connection."""
import subprocess
from typing import Annotated, Literal

import anyio
import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from siftfetch import mcp_images, tools, web_images
from siftfetch.host_flow_tools import _Handle
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable


_ImageId = Annotated[str, Field(pattern=r"^[0-9a-f]{24}$", min_length=24, max_length=24)]


def register_images(server: MCPServer, flow: ResearchFlow) -> None:
    @server.tool()
    async def page_image_inventory(handle: _Handle) -> dict:
        """List capture-local image IDs and marked alt text without fetching images."""
        try:
            inventory = await anyio.to_thread.run_sync(web_images.image_inventory, flow, handle)
        except SnapshotUnavailable:
            return {"status": "unavailable"}
        return {"status": "ok", "image_ids": list(inventory.ids), "content": inventory.content,
                "truncated": inventory.truncated}

    @server.tool()
    async def read_page_image(handle: _Handle, image_id: _ImageId,
                              operation: Literal["ocr", "describe"]) -> dict:
        """Fetch one image listed in this capture and return marked local OCR or description."""
        def read():
            try:
                flow._capture(handle, renew=False)
                backend = mcp_images._backend(operation)
                if backend is None:
                    return {"status": "backend_unavailable"}
                content = web_images.read_image(flow, handle, image_id, **backend)
            except SnapshotUnavailable:
                return {"status": "unavailable"}
            except httpx.HTTPStatusError as exc:
                return {"status": "http_error", "content": tools._http_failure(exc, "Read image")}
            except (KeyError, RuntimeError, ImportError, OSError, ValueError, subprocess.SubprocessError):
                return {"status": "image_unavailable"}
            return {"status": "ok", "content": content}

        result = await anyio.to_thread.run_sync(tools.guarded, read, "Read image")
        return {"status": "network_error", "content": result} if isinstance(result, str) else result
