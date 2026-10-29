"""Bounded injection sightings and read-only, offline review.

python -m siftfetch.sightings --since 7d --by category --json
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from urllib.parse import urlsplit

from siftfetch import egress_policy, saving
from siftfetch.injection_scan import safe_metadata, detection_excerpt

MAX_BYTES = 20 * 1024 * 1024
_lock = threading.Lock()
_warned = False


@lru_cache(maxsize=1)
def _suffixes():
    return {line.encode("idna").decode("ascii").lower()
            for line in Path(__file__).with_name("public_suffix_list.dat").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("//")}


def registrable_domain(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.rstrip(".").encode("idna").decode("ascii").lower().split(".")
    rules, count = _suffixes(), 1
    for i in range(len(labels)):
        tail = ".".join(labels[i:])
        if "!" + tail in rules:
            count = len(labels) - i - 1
            break
        if tail in rules or i and "*." + tail in rules:
            count = max(count, len(labels) - i + (1 if i and "*." + tail in rules else 0))
    return ".".join(labels[-(count + 1):])


def _safe_paths(base):
    for path in (base, *base.absolute().parents, base / "sightings.jsonl", base / "sightings.1.jsonl", base / ".sightings.lock"):
        if saving.is_link(path):
            raise OSError("sightings path is a link or junction")


@contextmanager
def _process_lock(base):
    """Serialize rotation across independent tool servers; bounded wait."""
    fd = os.open(base / ".sightings.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    acquired = False
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        deadline = time.monotonic() + 2.0
        while not acquired:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        yield
    finally:
        if acquired:
            if sys.platform == "win32":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _retry_in_use(action):
    """Windows refuses to rename or open a file another process (often a
    virus scanner) briefly holds; retry for up to half a second."""
    deadline = time.monotonic() + 0.5
    while True:
        try:
            return action()
        except PermissionError:
            if sys.platform != "win32" or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def record(scan, *, url="", tool="label"):
    """Best effort only: a log failure must never fail labeling or fetching."""
    global _warned
    if scan.risk == "none" and not any(d["location"].startswith("hidden:") for d in scan.detections):
        return
    try:
        config = egress_policy._config()
        if config.get("sightings", "on") == "off":
            return
        url = safe_metadata(url)
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        entry = {"time": saving._now(), "tool": safe_metadata(tool), "url": url,
                 "host": host, "domain": registrable_domain(host) if host else "",
                 "risk": scan.risk, "complete": scan.complete,
                 "patterns_version": scan.patterns_version, "detections": scan.detections[:10]}
        encoded = (json.dumps(entry, ensure_ascii=True) + "\n").encode("utf-8")
        cap = config.get("sightings_max_bytes", MAX_BYTES)
        # A single oversized record must not defeat the configured cap.
        if len(encoded) > cap:
            raise OSError("sightings record exceeds cap")
        with _lock:
            base = saving.data_dir()
            _safe_paths(base)
            base.mkdir(parents=True, exist_ok=True)
            with _process_lock(base):
                _safe_paths(base)
                path = base / "sightings.jsonl"
                if path.exists() and path.stat().st_size + len(encoded) > cap:
                    _retry_in_use(lambda: os.replace(path, base / "sightings.1.jsonl"))
                fd = _retry_in_use(lambda: os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY
                                                   | getattr(os, "O_BINARY", 0)
                                                   | getattr(os, "O_NOFOLLOW", 0), 0o600))
                with os.fdopen(fd, "ab") as stream:
                    stream.write(encoded)
    except Exception:
        if not _warned:
            _warned = True
            print("SiftFetch: could not write sightings log (further warnings suppressed).", file=sys.stderr)


def review(base=None, *, since=None, by="domain"):
    base = Path(base) if base is not None else saving.data_dir()
    _safe_paths(base)
    rows = []
    for name in ("sightings.1.jsonl", "sightings.jsonl"):
        path = base / name
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                    stamp = datetime.fromisoformat(row["time"].replace("Z", "+00:00"))
                    if since is None or stamp >= since:
                        rows.append(row)
                except (ValueError, KeyError, TypeError):
                    continue
    counts = Counter()
    for row in rows:
        keys = {d["type"] for d in row["detections"]} if by == "category" else {row["domain"] or "unknown"}
        counts.update(keys)
    return {"counts": dict(sorted(counts.items())), "newest": sorted(rows, key=lambda r: r["time"], reverse=True)[:10]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", help="age, e.g. 7d or 24h")
    parser.add_argument("--by", choices=("domain", "category"), default="domain")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    since = None
    if args.since:
        match = re.fullmatch(r"(\d+)([dh])", args.since)
        if not match:
            parser.error("--since must be a duration such as 7d or 24h")
        since = datetime.now(timezone.utc) - timedelta(hours=int(match[1]) * (24 if match[2] == "d" else 1))
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    result = review(since=since, by=args.by)
    if args.json:
        print(json.dumps(result, ensure_ascii=True))
    else:
        for key, count in result["counts"].items():
            print(f"{key}: {count}")
        for row in result["newest"]:
            print(f"{row['time']} {row['domain']} {row['risk']}")
            for detection in row["detections"]:
                print(f"  {detection['type']} ({detection['location']}): {detection_excerpt(detection['text'])}")


if __name__ == "__main__":
    main()
