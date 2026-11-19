from contextlib import nullcontext
import logging
from pathlib import Path
from types import SimpleNamespace
import sys

import anyio
import httpx
import pytest

from siftfetch import egress_policy, fetcher, host_flow, mcp_images, web_images
from test_host_flow import call
from test_web_images import image_page


def test_cross_call_image_selection_and_ownership(image_page, monkeypatch):
    _, _, seen, _ = image_page
    pixels_read = []

    def pixels(url):
        pixels_read.append(url)
        return nullcontext(object()), "https://snapshot.example/assets/second"

    monkeypatch.setattr(web_images, "_fetch_pixels", pixels)
    monkeypatch.setattr(mcp_images, "_describer", lambda image: "A chart.")

    async def scenario():
        async with host_flow.open_host_flow() as owner, host_flow.open_host_flow() as other:
            seen.clear()
            page = await call(owner, "open_page", url="https://snapshot.example/page")
            handle = page["handle"]
            inventory = await call(owner, "page_image_inventory", handle=handle)
            assert len(inventory["image_ids"]) == 4 and "Map" in inventory["content"]
            assert "[UNTRUSTED WEB CONTENT" in inventory["content"]
            assert "synthetic-marker" not in str(inventory)
            selection = dict(handle=handle, image_id=inventory["image_ids"][1], operation="describe")
            assert await call(other, "read_page_image", **selection) == {"status": "unavailable"}
            assert await call(other, "page_image_inventory", handle=handle) == {"status": "unavailable"}
            assert not pixels_read
            result = await call(owner, "read_page_image", **selection)
            assert result["status"] == "ok" and "A chart." in result["content"]
            assert "[UNTRUSTED WEB CONTENT" in result["content"] and "untrusted interpretation" in result["content"]
            assert "synthetic-marker" not in str(result)
            assert seen == ["/page"] and len(pixels_read) == 1
            await call(owner, "release_page", handle=handle)
            assert await call(owner, "read_page_image", **selection) == {"status": "unavailable"}
            assert len(pixels_read) == 1

    anyio.run(scenario)


def test_backend_off_and_unknown_image_do_not_fetch(image_page, monkeypatch):
    _, _, seen, _ = image_page

    async def scenario():
        async with host_flow.open_host_flow() as client:
            handle = (await call(client, "open_page", url="https://snapshot.example/page"))["handle"]
            seen.clear()
            monkeypatch.setattr(mcp_images, "_backend", lambda op: None)
            result = await call(client, "read_page_image", handle=handle, image_id="f" * 24, operation="ocr")
            assert result == {"status": "backend_unavailable"}
            monkeypatch.setattr(mcp_images, "_backend", lambda op: {"describe": lambda _: pytest.fail()})
            result = await call(client, "read_page_image", handle=handle, image_id="f" * 24, operation="describe")
            assert result == {"status": "image_unavailable"} and not seen

    anyio.run(scenario)


def test_selected_ocr_uses_local_backend_and_capture_provenance(image_page, monkeypatch):
    _, _, seen, _ = image_page

    class Pixels:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def save(self, buffer, *, format):
            assert format == "PNG"
            buffer.write(b"synthetic pixels")

    def recognize(args, **options):
        assert args == [sys.executable, "stdin", "stdout"]
        assert options["input"] == b"synthetic pixels"
        return SimpleNamespace(stdout=b"Chart legend")

    monkeypatch.setattr(mcp_images, "_backend", lambda op: {"tesseract": Path(sys.executable)} if op == "ocr" else {})
    monkeypatch.setattr(web_images, "_fetch_pixels", lambda url: (Pixels(), url))
    monkeypatch.setattr(web_images.subprocess, "run", recognize)

    async def scenario():
        async with host_flow.open_host_flow() as client:
            seen.clear()
            handle = (await call(client, "open_page", url="https://snapshot.example/flagged"))["handle"]
            inventory = await call(client, "page_image_inventory", handle=handle)
            result = await call(client, "read_page_image", handle=handle, image_id=inventory["image_ids"][0],
                                operation="ocr")
            assert result["status"] == "ok" and "[UNTRUSTED WEB CONTENT" in result["content"]
            assert "Chart legend" in result["content"] and "OCR transcription" in result["content"]
            assert "risk=none" not in result["content"] and seen == ["/flagged"]

    anyio.run(scenario)


def test_image_transport_failure_and_policy_denial_are_distinct(image_page, monkeypatch):
    async def scenario():
        async with host_flow.open_host_flow() as client:
            handle = (await call(client, "open_page", url="https://snapshot.example/page"))["handle"]
            image_id = (await call(client, "page_image_inventory", handle=handle))["image_ids"][0]
            args = dict(handle=handle, image_id=image_id, operation="describe")
            monkeypatch.setattr(mcp_images, "_describer", lambda _: pytest.fail())

            def fail(url):
                raise httpx.ConnectError("synthetic-private-marker")

            monkeypatch.setattr(web_images, "_fetch_pixels", fail)
            failure = await call(client, "read_page_image", **args)
            assert failure["status"] == "network_error" and "synthetic-private-marker" not in str(failure)

            def deny(url):
                raise egress_policy.EgressDenied(egress_policy.Decision("deny", "blocked_domain"))

            monkeypatch.setattr(web_images, "_fetch_pixels", deny)
            blocked = await client.call_tool("read_page_image", args)
            assert blocked.is_error

    anyio.run(scenario)


def test_image_http_error_omits_query_and_reason_from_result_and_sdk_logs(image_page, monkeypatch, caplog):
    transport = fetcher._PinnedTransport.handle_request
    requests = []

    def route(self, request):
        if request.url.path == "/assets/second":
            requests.append(request.url.query)
            return httpx.Response(404, stream=httpx.ByteStream(b""),
                                  extensions={"reason_phrase": b"remote-reason-marker"})
        return transport(self, request)

    def missing(url):
        with fetcher.checked_response(url, stream=True, public_only=True):
            pytest.fail("Expected a failing status")

    caplog.set_level(logging.INFO, logger="httpx")
    monkeypatch.setattr(fetcher._PinnedTransport, "handle_request", route)
    monkeypatch.setattr(web_images, "_fetch_pixels", missing)
    monkeypatch.setattr(mcp_images, "_describer", lambda _: pytest.fail("No pixels expected"))

    async def scenario():
        async with host_flow.open_host_flow() as client:
            page = await call(client, "open_page", url="https://snapshot.example/page")
            inventory = await call(client, "page_image_inventory", handle=page["handle"])
            result = await call(client, "read_page_image", handle=page["handle"],
                                image_id=inventory["image_ids"][1], operation="describe")
            assert result == {"status": "http_error", "content": "Read image failed (http_error): HTTP 404 Not Found."}

    anyio.run(scenario)
    assert requests == [b"version=synthetic-marker"]
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(204))) as client:
        client.get("https://unrelated.example/client-log-control")
    assert "client-log-control" in caplog.text
    assert "synthetic-marker" not in caplog.text
    assert "remote-reason-marker" not in caplog.text
