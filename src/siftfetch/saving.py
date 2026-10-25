"""Where fetched pages and downloads are kept, and the record of each save.

The data folder is separate from the policy folder: agents are denied reading
the policy folder, and they need to read what they saved. ``SIFTFETCH_DATA``
moves it; the default is ``%LOCALAPPDATA%\\siftfetch`` on Windows and
``~/.local/share/siftfetch`` elsewhere.

- ``saved/``: pages saved with ``fetch_and_save``, as Markdown.
- ``quarantine/``: pages graded high-risk, held as JSON for the owner to
  review. Nothing in it is ever written to ``saved/``.
- ``downloads/``: files from ``download_to_staging``.
- ``saved-ledger.jsonl``: one line per save (path, URL, risk grade, time),
  so anything that later reads ``saved/`` can tell web content apart.
"""

from __future__ import annotations

import json
import os
import random
import re
import string
import sys
from datetime import datetime, timezone
from pathlib import Path


class SaveError(RuntimeError):
    """A page could not be saved or quarantined."""


def data_dir() -> Path:
    moved = os.environ.get("SIFTFETCH_DATA")
    if moved:
        return Path(moved)
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "siftfetch"
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "siftfetch"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str, limit: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:limit].strip("-") or "page"


def _safe_name(name: str) -> str:
    """A file name chosen by an agent, kept inside the folder it names."""
    parts = [p for p in re.split(r"[\\/]+", name) if p and p not in (".", "..")]
    if not parts:
        raise SaveError("name is empty")
    stem = _slug(Path(parts[-1]).stem, 80)
    folders = [_slug(p, 40) for p in parts[:-1]]
    return "/".join([*folders, stem + ".md"])


def quarantine(content: str, url: str, title: str, scan: dict, tool: str) -> dict:
    """Hold one page for owner review. The cleaned text is kept intact."""
    qdir = data_dir() / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    path = qdir / f"{stamp}-{suffix}_{_slug(url)}.json"
    record = {"status": "quarantined", "quarantined_at": _now(), "tool": tool,
              "url": url, "title": title, **scan, "content": content}
    try:
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        raise SaveError(f"quarantine write failed: {exc}") from exc
    return {"status": "quarantined", "path": str(path), "risk": scan.get("risk")}


def save(content: str, url: str, name: str, scan: dict, overwrite: bool = False) -> dict:
    """Save a page that passed the grade, and record it in the ledger."""
    base = data_dir()
    rel = _safe_name(name)
    path = base / "saved" / rel
    if path.exists() and not overwrite:
        return {"status": "exists", "path": str(path)}
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(content, encoding="utf-8")
        with (base / "saved-ledger.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"path": rel, "url": url, "saved_at": _now(),
                                 "provenance": "untrusted-web", **scan}) + "\n")
    except OSError as exc:
        raise SaveError(f"save failed: {exc}") from exc
    return {"status": "saved", "path": str(path), "risk": scan.get("risk")}
