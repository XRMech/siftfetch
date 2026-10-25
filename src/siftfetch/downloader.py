"""Policy-checked binary downloads into the staging area.

The guarded replacement for ``curl -o``: every hop passes the egress policy
(through ``fetcher.checked_response``), the size and time limits are set by
the service, the file name is chosen by the service, and nothing downloaded
is ever executed or extracted here.
"""

import hashlib
import json
import os
import secrets
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import httpx
import pyexpat

from siftfetch.fetcher import _decoded, checked_response
from siftfetch.saving import is_link

# Callers may lower these, never raise them.
HARD_MAX_BYTES = 50_000_000
HARD_MAX_SECONDS = 120.0

_EXTENSIONS = {"pdf": "pdf", "html": "html", "text": "txt", "json": "json",
               "xml": "xml", "zip": "zip"}

# expat >= 2.4.1 caps entity amplification (billion laughs), which makes the
# stdlib parser safe for validating untrusted XML without defusedxml.
_EXPAT_SAFE = tuple(int(p) for p in pyexpat.EXPAT_VERSION.split("_")[1].split(".")) >= (2, 4, 1)

# html/text must decode almost cleanly; a binary served as text/html does not.
_MAX_REPLACEMENT_RATIO = 0.001


class DownloadRejected(ValueError):
    """The download was refused or discarded; ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"Download rejected ({reason}). {detail}".strip())
        self.reason = reason


def _safe_dir(staging_dir: Path) -> Path:
    """The downloads dir, refusing any symlink or junction on the way to it."""
    downloads = staging_dir / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    for path in (downloads, staging_dir):
        if is_link(path):
            raise DownloadRejected("unsafe_staging", f"{path.name} is a link or junction.")
    return downloads


def _charset(content_type: str) -> str:
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            return value.strip("\"'")
    return "utf-8"


def _validate(expect: str, data: bytes, content_type: str) -> None:
    if expect == "pdf":
        ok = data.startswith(b"%PDF-")
    elif expect == "zip":
        ok = data.startswith((b"PK\x03\x04", b"PK\x05\x06"))
    elif expect == "json":
        try:
            json.loads(data.decode("utf-8"))
            ok = True
        except (UnicodeDecodeError, ValueError):
            ok = False
    elif expect == "xml":
        if not _EXPAT_SAFE:
            raise DownloadRejected("unsupported", "XML validation needs expat >= 2.4.1.")
        try:
            ElementTree.fromstring(data)
            ok = True
        except ElementTree.ParseError:
            ok = False
    else:  # html, text
        try:
            text = data.decode(_charset(content_type), errors="replace")
        except LookupError:
            text = data.decode("utf-8", errors="replace")
        ok = text.count("�") <= max(1, len(text)) * _MAX_REPLACEMENT_RATIO
    if not ok:
        raise DownloadRejected("type_mismatch", f"Content is not valid {expect}.")


def download_to_staging(url: str, staging_dir: Path, expect: str,
                        max_bytes: int = HARD_MAX_BYTES, browser: str = "none") -> dict:
    """Download ``url`` into ``staging_dir/downloads`` and validate it.

    Returns ``{path, bytes, sha256, content_type}``. Raises EgressDenied when
    the policy refuses a hop and DownloadRejected for size, time, type or
    staging-safety failures; a rejected file is deleted before raising.
    """
    if expect not in _EXTENSIONS:
        raise DownloadRejected("bad_request", f"expect must be one of {sorted(_EXTENSIONS)}.")
    limit = min(int(max_bytes), HARD_MAX_BYTES)
    if limit <= 0:
        raise DownloadRejected("bad_request", "max_bytes must be positive.")
    downloads = _safe_dir(Path(staging_dir))
    deadline = time.monotonic() + HARD_MAX_SECONDS

    part = downloads / f".part-{secrets.token_hex(8)}"
    fd = os.open(part, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    digest = hashlib.sha256()
    size = 0
    timeout = DownloadRejected("timeout", f"Took longer than {HARD_MAX_SECONDS:g}s.")
    try:
        with os.fdopen(fd, "wb") as out:
            try:
                with checked_response(url, browser=browser, stream=True,
                                      deadline=deadline) as resp:
                    content_type = resp.headers.get("content-type", "")
                    # Decoded in bounded steps, so a compression bomb hits the
                    # limit before it can fill memory.
                    for chunk in _decoded(resp):
                        size += len(chunk)
                        if size > limit:
                            raise DownloadRejected("too_large", f"More than {limit} bytes.")
                        if time.monotonic() > deadline:
                            raise timeout
                        digest.update(chunk)
                        out.write(chunk)
            except (httpx.TransportError, httpx.StreamError) as exc:
                # The deadline watchdog ends a stalled read by closing the client.
                if time.monotonic() >= deadline:
                    raise timeout from exc
                raise
        _validate(expect, part.read_bytes(), content_type)
        sha = digest.hexdigest()
        final = downloads / f"{sha[:16]}.{_EXTENSIONS[expect]}"
        os.replace(part, final)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return {"path": str(final), "bytes": size, "sha256": sha, "content_type": content_type}
