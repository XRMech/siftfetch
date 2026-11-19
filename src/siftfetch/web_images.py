"""On-demand raster image evidence from a public ResearchFlow capture."""
from dataclasses import dataclass
import asyncio
from hashlib import blake2s
from io import BytesIO
from itertools import islice
from pathlib import Path
import subprocess
import time
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from siftfetch import fetcher
from siftfetch.research_flow import ResearchFlow, _evidence


_MAX_IMAGES = 128
_MAX_BYTES = 4 * 1024 * 1024
_MAX_PIXELS = 8_000_000
_FORMATS = {"image/png": "PNG", "image/jpeg": "JPEG"}


@dataclass(frozen=True)
class ImageInventory:
    ids: tuple[str, ...]
    content: str
    truncated: bool


def _entries(item):
    soup = BeautifulSoup(item.html, "lxml")
    base = soup.find("base", href=True)
    try:
        base_url = urljoin(item.url, base["href"]) if base else item.url
    except ValueError:
        return
    for pos, tag in enumerate(soup.find_all("img", src=True)):
        src = tag["src"].strip()
        if not src:
            continue
        try:
            url = urljoin(base_url, src)
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None:
                continue
        except ValueError:
            continue
        image_id = blake2s(f"{item.handle}/{pos}".encode(), digest_size=12).hexdigest()
        yield image_id, url, tag.get("alt", "")


def image_inventory(flow: ResearchFlow, handle: str) -> ImageInventory:
    """List up to 128 static img sources from this capture without loading any image."""
    with flow._operations:
        item = flow._capture(handle)
        ids, lines = [], []
        truncated = False
        for image_id, _, alt in _entries(item):
            if len(ids) == _MAX_IMAGES:
                truncated = True
                break
            ids.append(image_id)
            if len(alt) > 256:
                truncated = True
                alt = alt[:256] + " [alt text clipped]"
            lines.append(f"{image_id}  {alt}")
        text = "\n".join(lines) or "No supported image sources."
        content = _evidence(text, item.url, "image_inventory", item.initial_scan, complete=not truncated)
        return ImageInventory(tuple(ids), content, truncated)


def _fetch_pixels(url):
    try:
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise RuntimeError("Install siftfetch[images] to read image pixels.") from exc
    deadline = time.monotonic() + 30
    with fetcher.checked_response(url, stream=True, deadline=deadline, public_only=True) as resp:
        mime = resp.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if resp.status_code != 200 or mime not in _FORMATS:
            raise ValueError("Expected a complete PNG or JPEG image")
        data = BytesIO()
        for chunk in fetcher._decoded(resp):
            if data.tell() + len(chunk) > _MAX_BYTES or time.monotonic() >= deadline:
                raise ValueError("Image exceeded the retrieval limit")
            data.write(chunk)
        source = urlsplit(str(resp.url))._replace(query="", fragment="").geturl()
    data.seek(0)
    with Image.open(data, formats=[_FORMATS[mime]]) as image:
        if image.width * image.height > _MAX_PIXELS or getattr(image, "n_frames", 1) != 1:
            raise ValueError("Image exceeded the pixel limit or contains multiple frames")
        ImageOps.exif_transpose(image, in_place=True)
        if image.has_transparency_data:
            with image.convert("RGBA") as rgba:
                pixels = Image.new("RGB", rgba.size, "white")
                pixels.paste(rgba, mask=rgba.getchannel("A"))
        else:
            pixels = image.convert("RGB")
        pixels.info.clear()
        return pixels, source


async def _windows_text(pixels):
    from winrt.windows.graphics.imaging import BitmapPixelFormat, SoftwareBitmap
    from winrt.windows.media.ocr import OcrEngine
    from winrt.windows.storage.streams import DataWriter

    engine = OcrEngine.try_create_from_user_profile_languages()
    if engine is None:
        raise RuntimeError("No installed Windows OCR recognition language is available")
    if max(pixels.size) > OcrEngine.max_image_dimension:
        raise ValueError("Image exceeds the Windows OCR dimension limit")
    with pixels.convert("L") as gray, DataWriter() as writer:
        writer.write_bytes(gray.tobytes())
        bitmap = SoftwareBitmap.create_copy_from_buffer(writer.detach_buffer(), BitmapPixelFormat.GRAY8,
                                                       gray.width, gray.height)
        with bitmap:
            result = await asyncio.wait_for(engine.recognize_async(bitmap), timeout=30)
            return result.text


def read_image(flow: ResearchFlow, handle: str, image_id: str, *, tesseract=None, windows_ocr=False,
               describe=None) -> str:
    """Read one image with an explicitly selected local OCR executable or description callable."""
    if sum((tesseract is not None, bool(windows_ocr), describe is not None)) != 1:
        raise ValueError("Select one local image backend")
    if tesseract is not None:
        exe = Path(tesseract)
        if not exe.is_absolute() or not exe.is_file():
            raise ValueError("Supply the absolute path of the installed Tesseract executable")
    elif windows_ocr:
        try:
            import winrt.windows.media.ocr
        except ImportError as exc:
            raise RuntimeError("Install siftfetch[windows-ocr] on Windows to use OS OCR") from exc
    elif not callable(describe):
        raise TypeError("describe must accept one RGB image")

    with flow._operations:
        item = flow._capture(handle)
        for candidate, url, _ in islice(_entries(item), _MAX_IMAGES):
            if candidate == image_id:
                break
        else:
            raise KeyError("Image unavailable")
        pixels, source = _fetch_pixels(url)
        with pixels:
            if windows_ocr:
                text = asyncio.run(_windows_text(pixels))
                kind = "OCR transcription of page-derived image"
            elif tesseract is not None:
                encoded = BytesIO()
                pixels.save(encoded, format="PNG")
                result = subprocess.run([str(exe), "stdin", "stdout"], cwd=exe.parent, input=encoded.getvalue(),
                                        capture_output=True, timeout=30, check=True)
                text = result.stdout.decode("utf-8", errors="replace")
                kind = "OCR transcription of page-derived image"
            else:
                text = describe(pixels)
                kind = "Generated image description (untrusted interpretation)"
        if not isinstance(text, str):
            raise TypeError("Image backend must return text")
        body = (f"{kind}\nPage: {item.url}\nPage captured: {item.captured_at}\n"
                f"Image ID: {image_id}\n\n{text[:30000]}")
        return _evidence(body, source, "read_image", item.initial_scan, complete=len(text) <= 30000)
