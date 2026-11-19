"""Call-local MCP access to reviewed static image sources."""
import hashlib
import hmac
from itertools import islice
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

from siftfetch import web_images
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable, _evidence

_key = secrets.token_bytes(32)
_describer = None


def configure_image_describer(describe):
    """Install a trusted local pixel-to-text callable during server startup."""
    if describe is not None and not callable(describe):
        raise TypeError("Expected a local image description callable")
    global _describer
    _describer = describe


def _backend(operation):
    if operation == "describe":
        describe = _describer
        if describe is None:
            return None

        def local_description(pixels):
            try:
                result = describe(pixels)
            except Exception:
                raise RuntimeError("Image description failed") from None
            if not isinstance(result, str):
                raise ValueError("Image description must return text")
            return result

        return {"describe": local_description}
    path = os.environ.get("SIFTFETCH_MCP_TESSERACT")
    if path:
        exe = Path(path)
        if not path.startswith(("\\\\", "//")) and exe.is_absolute() and exe.is_file():
            return {"tesseract": exe}
        return None
    return {"windows_ocr": True} if sys.platform == "win32" else None


def _inventory_token(page_url, entries, overflow):
    digest = hmac.new(_key, digestmod=hashlib.sha256)

    def add(value):
        data = value.encode("utf-8")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)

    add(page_url)
    add(str(overflow))
    for _, url, alt in entries:
        add(url)
        add(alt)
    return digest.hexdigest()


def page_images(url, operation="inventory", image_number=None, expected_inventory=None):
    """Inspect a public page inventory or read a single reviewed entry."""
    if operation not in ("inventory", "ocr", "describe"):
        raise ValueError("Unknown image operation")
    if operation == "inventory":
        if image_number is not None or expected_inventory is not None:
            raise ValueError("Inventory takes no selection")
    elif (type(image_number) is not int or not 1 <= image_number <= web_images._MAX_IMAGES
          or not isinstance(expected_inventory, str) or not re.fullmatch("[0-9a-f]{64}", expected_inventory)):
        raise ValueError("Supply a listed image number and inventory token")
    with ResearchFlow() as flow:
        first = flow.fetch(url)
        if not first.handle:
            return {"status": "call_only"}
        try:
            with flow._operations:
                item = flow._capture(first.handle)
                entries = list(islice(web_images._entries(item), web_images._MAX_IMAGES + 1))
                overflow = len(entries) > web_images._MAX_IMAGES
                entries = entries[:web_images._MAX_IMAGES]
                token = _inventory_token(item.url, entries, overflow)
                if operation == "inventory" or not hmac.compare_digest(token, expected_inventory):
                    truncated = overflow or any(len(alt) > 256 for _, _, alt in entries)
                    lines = [f"{n}. {alt[:256]}" for n, (_, _, alt) in enumerate(entries, 1)]
                    content = _evidence("\n".join(lines) or "No supported image sources.", item.url,
                                        "image_inventory", item.initial_scan, complete=not truncated)
                    return {"status": "ok" if operation == "inventory" else "inventory_changed",
                            "inventory_token": token, "count": len(entries), "content": content,
                            "truncated": truncated, "captured_at": first.captured_at}
                if image_number > len(entries):
                    return {"status": "image_unavailable"}
                image_id = entries[image_number - 1][0]
            backend = _backend(operation)
            if backend is None:
                return {"status": "backend_unavailable"}
            try:
                content = web_images.read_image(flow, first.handle, image_id, **backend)
            except (RuntimeError, ImportError, OSError, ValueError, subprocess.SubprocessError):
                return {"status": "image_unavailable"}
            return {"status": "ok", "content": content, "captured_at": first.captured_at}
        except SnapshotUnavailable:
            return {"status": "capture_unavailable"}
