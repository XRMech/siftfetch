"""Opt-in, process-local reuse of explicitly public HTML for Python callers."""
from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import html
from hashlib import blake2s
import secrets
import sys
import threading
import time

from siftfetch import egress_policy, injection_scan, tools


# Initial ceilings for this opt-in API. One capture per flow. The global
# limits cover retained captures, not in-flight fetches or temporary renders.
_MAX_CAPTURE = 2 * 1024 * 1024
_MAX_TOTAL = 32 * 1024 * 1024
_MAX_ENTRIES = 32
_IDLE_SECONDS = 60
_MAX_REPORTS_PER_CAPTURE = 32
_VIEWS = ("auto", "readability", "full", "raw")
_BREADTH = ("readability", "auto", "full", "raw", "source")


@dataclass(frozen=True)
class PageRead:
    content: str
    handle: str | None
    captured_at: str | None
    truncated: bool | None = None

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode("utf-8"))


@dataclass
class _Capture:
    handle: str
    url: str
    html: str
    captured_at: str
    size: int
    expires: float
    initial_scan: injection_scan.Scan
    last_view: str | None = None
    escalated: bool = False
    missing_reported: bool = False
    reported_candidates: set[bytes] = field(default_factory=set)


class ViewUsage:
    """Aggregate richer-view requests for an opt-in, process-local measurement."""

    def __init__(self):
        self._lock = threading.Lock()
        self._captures = 0
        self._escalated_captures = 0
        self._transitions = Counter()

    def _start(self, item, view):
        item.last_view = view
        with self._lock:
            self._captures += 1

    def _read(self, item, view):
        previous = item.last_view
        item.last_view = view
        if _BREADTH.index(view) > _BREADTH.index(previous):
            with self._lock:
                self._transitions[(previous, view)] += 1
                if not item.escalated:
                    item.escalated = True
                    self._escalated_captures += 1

    def snapshot(self) -> dict:
        """Return detached JSON-compatible totals; transitions are grouped by view pair."""
        with self._lock:
            transitions = {}
            for (previous, view), count in self._transitions.items():
                transitions.setdefault(previous, {})[view] = count
            return {"captures": self._captures, "escalated_captures": self._escalated_captures,
                    "transitions": transitions}


_captures: OrderedDict[object, _Capture] = OrderedDict()
_changed = threading.Condition()
_worker = None


def _expire():
    global _worker
    with _changed:
        while _captures:
            oldest = next(iter(_captures.values()))
            remaining = oldest.expires - time.monotonic()
            if remaining > 0:
                _changed.wait(remaining)
            else:
                _captures.popitem(last=False)
        _worker = None


def _eligible(resp):
    url = resp.url
    directives = {part.partition("=")[0].strip().lower()
                  for part in resp.headers.get("cache-control", "").split(",")}
    vary = {part.strip().lower() for part in resp.headers.get("vary", "").split(",")}
    return (resp.extensions.get("siftfetch_public_direct") is True
            and resp.status_code == 200 and url.scheme == "https"
            and not (url.userinfo or url.query or url.fragment)
            and "public" in directives and directives.isdisjoint({"no-store", "private", "no-cache"})
            and vary.isdisjoint({"*", "authorization", "cookie"})
            and "www-authenticate" not in resp.headers
            and "set-cookie" not in resp.headers and "content-range" not in resp.headers
            and not any(key in resp.request.headers for key in ("authorization", "cookie"))
            and resp.headers.get("content-type", "").partition(";")[0].strip().lower() == "text/html"
            and not egress_policy.destination_allowed(str(url)))


class SnapshotUnavailable(KeyError):
    """The current flow has no live capture for the supplied handle."""


class ResearchFlow:
    """Own one anonymous page snapshot. Use as a context manager or call close()."""

    def __init__(self, *, usage: ViewUsage | None = None):
        if usage is not None and not isinstance(usage, ViewUsage):
            raise TypeError("usage must be a ViewUsage instance or None")
        self._usage = usage
        self._key = object()
        self._closed = False
        self._operations = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def release(self):
        with self._operations, _changed:
            _captures.pop(self._key, None)
            _changed.notify_all()

    def release_if_current(self, handle: str) -> None:
        """Release this flow's matching capture, ignoring missing or stale handles."""
        with self._operations, _changed:
            item = _captures.get(self._key)
            if item is not None and item.handle == handle:
                del _captures[self._key]
                _changed.notify_all()

    def report_missing_evidence(self, handle: str) -> bool:
        """Record one explicit report per live capture when failed-site recording is enabled."""
        from siftfetch import site_cases
        with self._operations:
            item = self._capture(handle)
            if item.missing_reported or not site_cases.record_failure(item.url, "missing_evidence"):
                return False
            item.missing_reported = True
            return True

    def report_candidate(self, handle: str, excerpt: str) -> bool:
        """Archive an exact observed passage as an unreviewed researcher report."""
        from siftfetch import site_cases
        with self._operations:
            item = self._capture(handle)
            try:
                if egress_policy._config().get("case_study_sites") != "on":
                    return False
            except (OSError, ValueError, egress_policy.PolicyError):
                return False
            if (not isinstance(excerpt, str) or not 1 <= len(excerpt) <= site_cases.MAX_EXCERPT_CHARS
                    or not excerpt.strip()):
                raise ValueError("Supply a nonempty excerpt within the case-study character limit")
            if excerpt not in item.html:
                cleaned = tools.clean_html(item.html, url=item.url, max_chars=0,
                                           include_metadata=False, include_links=False)
                if excerpt not in cleaned:
                    raise ValueError("The excerpt was not found in the captured page")
            key = blake2s(excerpt.encode("utf-8"), digest_size=16).digest()
            if key in item.reported_candidates or len(item.reported_candidates) >= _MAX_REPORTS_PER_CAPTURE:
                return False
            self._capture(handle, renew=False)
            if not site_cases.record_reported_candidate(url=item.url, excerpt=excerpt, captured_at=item.captured_at):
                return False
            item.reported_candidates.add(key)
            return True

    def close(self):
        with self._operations, _changed:
            self._closed = True
            _captures.pop(self._key, None)
            _changed.notify_all()

    def fetch(self, url: str, *, extract="auto") -> PageRead:
        """Read normally. Only a direct, eligible response receives a reusable handle."""
        if extract not in _VIEWS:
            raise ValueError(f"Unknown extraction view: {extract!r}")
        with self._operations:
            if self._closed:
                raise RuntimeError("Research flow is closed")
            source = url
            stamp = None

            def observe(resp):
                nonlocal source, stamp
                if _eligible(resp):
                    source = str(resp.url)
                    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

            text, raw = tools._fetch_url_raw(url, "none", 30000, 0, "content", None,
                                             extract, False, "unattended", observe)
            return self._finish_read(text, raw, source, stamp, extract)

    def _finish_read(self, text, raw, source, stamp, extract):
        # Caller holds the flow operation lock across capture and replacement.
        global _worker
        labeled, scan = tools.label(text, raw, url=source, tool="fetch_url")
        tools._record_page_scan(text, scan, captured_at=stamp)
        content = injection_scan.envelope(labeled, source, scan)
        truncated = getattr(text, "truncated", None)
        size = sys.getsizeof(raw) + sys.getsizeof(source)
        with _changed:
            _captures.pop(self._key, None)
            _changed.notify_all()
            if stamp is None or size > min(_MAX_CAPTURE, _MAX_TOTAL):
                return PageRead(content, None, None, truncated)
            while (len(_captures) >= _MAX_ENTRIES
                   or sum(item.size for item in _captures.values()) + size > _MAX_TOTAL):
                _captures.popitem(last=False)
            handle = secrets.token_urlsafe(24)
            item = _Capture(handle, source, raw, stamp, size, time.monotonic() + _IDLE_SECONDS,
                            replace(scan, spans=[], detections=[]))
            _captures[self._key] = item
            if _worker is None:
                _worker = threading.Thread(target=_expire, daemon=True)
                _worker.start()
            if self._usage is not None:
                self._usage._start(item, extract)
            return PageRead(content, handle, stamp, truncated)

    def _capture(self, handle, *, renew=True):
        with _changed:
            item = _captures.get(self._key)
            if item is None or item.handle != handle or item.expires <= time.monotonic():
                raise SnapshotUnavailable("Snapshot unavailable")
            if renew:
                item.expires = time.monotonic() + _IDLE_SECONDS
                _captures.move_to_end(self._key)
                _changed.notify_all()
            return item

    def read(self, handle: str, *, extract="auto", max_chars=30000) -> PageRead:
        """Render the capture again. An unavailable handle never triggers a fetch."""
        if extract not in (*_VIEWS, "source"):
            raise ValueError(f"Unknown extraction view: {extract!r}")
        with self._operations:
            item = self._capture(handle)
            result = _render(item, extract, max_chars, record=True)
            if self._usage is not None:
                self._usage._read(item, extract)
            return result

    def view_sizes(self, handle: str, *, max_chars=30000) -> dict[str, int]:
        """Measure each enveloped response locally, without recording extra sightings."""
        with self._operations:
            item = self._capture(handle)
            return {view: _render(item, view, max_chars, record=False).size_bytes
                    for view in (*_VIEWS, "source")}


def _with_page_grade(scan, initial):
    return replace(scan, risk=max((initial.risk, scan.risk), key=injection_scan.RISK_ORDER.index),
                   complete=initial.complete and scan.complete,
                   categories=tuple(sorted(set(initial.categories + scan.categories))),
                   hidden_categories=tuple(sorted(set(initial.hidden_categories + scan.hidden_categories))))


def _evidence(text, source, tool, initial_scan, complete=True, *, raw=""):
    """Label, grade and display a derived snapshot result as inert text."""
    from siftfetch.sightings import record
    spotlight = egress_policy._config().get("spotlight", "paragraph")
    labeled, scan = tools._label_content(text, raw, complete=complete, spotlight=spotlight)
    scan = _with_page_grade(scan, initial_scan)
    record(scan, url=source, tool=tool)
    code = "\n".join("    " + html.escape(line, quote=False) for line in labeled.splitlines())
    return injection_scan.envelope(injection_scan.LabeledText("\n\n" + code), source, scan)


def _render(item, view, max_chars, *, record):
    if type(max_chars) is not int or max_chars < 0:
        raise ValueError("max_chars must be a nonnegative integer")
    complete = True
    if view == "source":
        text = item.html[:max_chars] if max_chars else item.html
        complete = len(text) == len(item.html)
        truncated = not complete
    else:
        text = tools.clean_html(item.html, url=item.url, extract=view, max_chars=max_chars)
        truncated = text.truncated
    spotlight = egress_policy._config().get("spotlight", "paragraph")
    labeled, scan = tools._label_content(text, item.html, complete=complete, spotlight=spotlight)
    # Presentation limits and alternate views can omit evidence from the first read.
    scan = _with_page_grade(scan, item.initial_scan)
    if view == "source":
        # Indent every line as Markdown code and escape HTML for plaintext/HTML clients.
        heading = f"Decoded HTML source ({len(text)} of {len(item.html)} characters shown)"
        code = "\n".join("    " + html.escape(line, quote=False) for line in labeled.splitlines())
        labeled = injection_scan.LabeledText(heading + "\n\n" + code)
    if record:
        from siftfetch.sightings import record as record_sighting
        record_sighting(scan, url=item.url, tool="fetch_url")
    content = injection_scan.envelope(labeled, item.url, scan)
    return PageRead(content, item.handle, item.captured_at, truncated)
