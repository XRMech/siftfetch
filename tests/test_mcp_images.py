from contextlib import nullcontext
from io import BytesIO
import json
import sys

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from siftfetch import mcp_images, server, web_images
from test_web_images import image_page


def call(path="/page", **options):
    result = anyio.run(server.mcp.call_tool, "fetch_page_images",
                       {"url": "https://snapshot.example" + path, **options})
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)


def test_inventory_and_selected_description(image_page, monkeypatch):
    _, _, seen, _ = image_page
    inventory = call()
    assert inventory["count"] == 4 and "1. Map" in inventory["content"]
    assert inventory["content"].startswith("[UNTRUSTED WEB CONTENT") and "synthetic-marker" not in str(inventory)
    assert seen == ["/page"] * 2
    selected = []
    def pixels(url):
        selected.append(url)
        return nullcontext(object()), "https://snapshot.example/assets/second"
    monkeypatch.setattr(web_images, "_fetch_pixels", pixels)
    monkeypatch.setattr(mcp_images, "_describer", lambda image: "Label on second image")
    result = call(operation="describe", image_number=2, expected_inventory=inventory["inventory_token"])
    assert result["status"] == "ok" and "Label on second image" in result["content"]
    assert "UNTRUSTED WEB CONTENT" in result["content"] and "synthetic-marker" not in str(result)
    assert selected == ["https://snapshot.example/assets/second?version=synthetic-marker"]
    previous = web_images._entries
    def reordered(item):
        yield from reversed(list(previous(item)))
    monkeypatch.setattr(web_images, "_entries", reordered)
    changed = call(operation="describe", image_number=2, expected_inventory=inventory["inventory_token"])
    assert changed["status"] == "inventory_changed" and changed["inventory_token"] != inventory["inventory_token"]
    assert len(selected) == 1


def test_missing_backend_and_invalid_selection(image_page, monkeypatch):
    _, _, seen, _ = image_page
    inventory = call()
    monkeypatch.setattr(mcp_images, "_describer", None)
    assert call(operation="describe", image_number=1, expected_inventory=inventory["inventory_token"]) == {
        "status": "backend_unavailable"}
    with pytest.raises(ValueError):
        mcp_images.page_images("https://snapshot.example/page", "ocr", 1, "unchecked")
    assert seen == ["/page"] * 3


@pytest.mark.skipif(sys.platform != "win32", reason="Windows OCR integration")
def test_registered_windows_ocr(image_page, monkeypatch):
    Image = pytest.importorskip("PIL.Image")
    ImageDraw = pytest.importorskip("PIL.ImageDraw")
    ImageFont = pytest.importorskip("PIL.ImageFont")
    ocr = pytest.importorskip("winrt.windows.media.ocr")
    if ocr.OcrEngine.try_create_from_user_profile_languages() is None:
        pytest.skip("No installed Windows OCR language")
    monkeypatch.delenv("SIFTFETCH_MCP_TESSERACT", raising=False)
    _, _, seen, images = image_page
    with Image.new("RGB", (720, 160), "white") as page:
        ImageDraw.Draw(page).text((25, 20), "FIELD NOTES", font=ImageFont.truetype("arial.ttf", 78), fill="black")
        buf = BytesIO()
        page.save(buf, format="PNG")
    images["/assets/first"] = ("image/png", buf.getvalue())
    inventory = call()
    result = call(operation="ocr", image_number=1, expected_inventory=inventory["inventory_token"])
    assert result["status"] == "ok" and "FIELD NOTES" in result["content"].upper()
    assert seen == ["/page", "/page", "/page", "/assets/first"]


def test_private_page_and_backend_values_stay_out_of_result(image_page, monkeypatch):
    _, _, seen, _ = image_page
    assert call("/page?test=synthetic") == {"status": "call_only"}
    inventory = call()
    def failed_backend(pixels):
        raise LookupError("private-backend-path-marker")
    monkeypatch.setattr(mcp_images, "_describer", failed_backend)
    monkeypatch.setattr(web_images, "_fetch_pixels", lambda url: (nullcontext(object()), url))
    result = call(operation="describe", image_number=1, expected_inventory=inventory["inventory_token"])
    assert result == {"status": "image_unavailable"}
    assert seen == ["/page"] * 4


def test_image_redirect_remains_guarded(image_page, monkeypatch):
    pytest.importorskip("PIL.Image")
    _, _, seen, _ = image_page
    monkeypatch.setattr(mcp_images, "_describer", lambda _: pytest.fail("blocked pixels reached backend"))
    inventory = call()
    for number in (3, 4):
        with pytest.raises(ToolError):
            anyio.run(server.mcp.call_tool, "fetch_page_images",
                           {"url": "https://snapshot.example/page", "operation": "describe",
                            "image_number": number, "expected_inventory": inventory["inventory_token"]})
    assert seen == ["/page", "/page", "/page", "/assets/redirect", "/page", "/assets/private"]
