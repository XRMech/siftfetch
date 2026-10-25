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
import secrets
import stat
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


def is_link(path: Path) -> bool:
    """A symlink, junction or other reparse point (False when absent)."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _safe_folder(base: Path, rel: str) -> Path:
    """Create ``base/rel`` and refuse it if any step below ``base`` is a link.

    A link planted in the data folder would send a write somewhere else.
    """
    folder = base
    for part in Path(rel).parts:
        folder = folder / part
        if is_link(folder):
            raise SaveError(f"{folder} is a link or junction; nothing was written")
        folder.mkdir(exist_ok=True)
    return folder


def _write_new(path: Path, text: str) -> bool:
    """Create the file; False if it already exists. Never follows a link."""
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as fh:
        fh.write(text.encode("utf-8"))
    return True


def quarantine(content: str, url: str, title: str, scan: dict, tool: str) -> dict:
    """Hold one page for owner review. The cleaned text is kept intact."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    record = {"status": "quarantined", "quarantined_at": _now(), "tool": tool,
              "url": url, "title": title, **scan, "content": content}
    try:
        data_dir().mkdir(parents=True, exist_ok=True)
        path = _safe_folder(data_dir(), "quarantine") / f"{stamp}-{suffix}_{_slug(url)}.json"
        if not _write_new(path, json.dumps(record, indent=2, ensure_ascii=False)):
            raise SaveError(f"quarantine name already taken: {path.name}")
    except OSError as exc:
        raise SaveError(f"quarantine write failed: {exc}") from exc
    return {"status": "quarantined", "path": str(path), "risk": scan.get("risk")}


def save(content: str, url: str, name: str, scan: dict, overwrite: bool = False) -> dict:
    """Save a page that passed the grade, and record it in the ledger."""
    base = data_dir()
    rel = _safe_name(name)
    try:
        base.mkdir(parents=True, exist_ok=True)
        folder = _safe_folder(base, str(Path("saved", rel).parent))
        path = folder / Path(rel).name
        if is_link(path):
            raise SaveError(f"{path} is a link or junction; nothing was written")
        if overwrite:
            # Written beside the target, then swapped in: replacing a path
            # replaces the name, never a file a link points to.
            part = folder / f".part-{secrets.token_hex(8)}"
            if not _write_new(part, content):
                raise SaveError("temporary file name collided; try again")
            try:
                os.replace(part, path)
            except OSError:
                part.unlink(missing_ok=True)
                raise
        elif not _write_new(path, content):
            return {"status": "exists", "path": str(path)}
        ledger = base / "saved-ledger.jsonl"
        if is_link(ledger):
            raise SaveError(f"{ledger} is a link or junction; the save was not recorded")
        with ledger.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"path": rel, "url": url, "saved_at": _now(),
                                 "provenance": "untrusted-web", **scan}) + "\n")
    except OSError as exc:
        raise SaveError(f"save failed: {exc}") from exc
    return {"status": "saved", "path": str(path), "risk": scan.get("risk")}
