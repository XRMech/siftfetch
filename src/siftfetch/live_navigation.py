"""Read a public snapshot in a short-lived, offline Chromium viewport."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
import secrets
import threading
import time

import anyio
from bs4 import BeautifulSoup

from siftfetch import browser_fetch, egress_policy, egress_proxy, hidden_text, live_viewport
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable, _evidence


_RENDER_URL = "https://snapshot.invalid/viewport"
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; sandbox")
_IDLE = 30
_LIFETIME = 120
_SLOTS = threading.BoundedSemaphore(2)
_MAX_ELEMENTS = 8_000
_MAX_INPUT = 512_000
_CLOSE_SECONDS = 5
_START_SECONDS = 25


@dataclass(frozen=True)
class Control:
    id: str
    kind: str


@dataclass(frozen=True)
class Viewport:
    revision: str
    content: str
    controls: tuple[Control, ...]
    captured_at: str
    truncated: bool


def _markup(item):
    if len(item.html.encode("utf-8")) > _MAX_INPUT:
        raise ValueError("Live viewport input exceeds its size limit")
    soup = BeautifulSoup(item.html, "lxml")
    if len(soup.find_all(True, limit=_MAX_ELEMENTS + 1)) > _MAX_ELEMENTS:
        raise ValueError("Live viewport input exceeds its element limit")
    for el in soup.find_all(["script", "noscript", "template", "iframe", "frame", "object",
                             "embed", "applet", "meta", "link", "base", "svg", "math", "canvas",
                             "video", "audio", "img", "picture", "input", "textarea", "select"]):
        el.decompose()
    # Retain semantic/layout structure and host-inspected ARIA associations.
    # Incoming markup supplies neither URLs to visit nor executable handlers.
    allowed = {"id", "class", "style", "role", "dir", "lang", "hidden", "open", "scope",
               "rowspan", "colspan", "aria-controls", "aria-labelledby", "aria-hidden"}
    for el in soup.find_all(True):
        el.attrs = {key: value for key, value in el.attrs.items() if key in allowed}
    return str(soup)


async def _open_page(stack, markup, settings):
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise browser_fetch.BrowserFetchUnavailable("Install siftfetch[browser] for live navigation") from exc
    proxy = stack.enter_context(egress_proxy.EgressProxy(offline=True))
    pw = await _start_driver(stack, async_playwright())
    browser = await pw.chromium.launch(channel=settings["browser"], headless=True,
                                       args=browser_fetch._CLOSED_SIDE_CHANNELS + proxy.launch_args)
    stack.push_async_callback(_bounded_close, browser.close)
    context = await browser.new_context(java_script_enabled=False, offline=True, service_workers="block",
                                        accept_downloads=False, viewport={"width": 1000, "height": 720})
    page = await context.new_page()
    pending = True

    async def gate(route):
        nonlocal pending
        request = route.request
        if (pending and request.method == "GET" and request.url == _RENDER_URL
                and request.resource_type == "document" and request.frame == page.main_frame):
            pending = False
            await route.fulfill(status=200, body=markup, headers={
                "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": _CSP,
                "Referrer-Policy": "no-referrer"})
        else:
            await route.abort("blockedbyclient")

    await context.route("**/*", gate)
    await context.route_web_socket("**/*", lambda ws: None)
    await page.goto(_RENDER_URL, wait_until="domcontentloaded", timeout=10_000)
    if pending or page.url != _RENDER_URL:
        raise RuntimeError("Offline viewport could not initialize")
    return page


async def _start_driver(stack, manager):
    # start() spawns the transport before returning a Playwright object.
    # Shield the handshake from native cancellation and give the viewport's
    # exit stack ownership before the first interruptible wait.
    starting = asyncio.create_task(manager.start())

    async def finish(transport):
        if starting.done() and not starting.cancelled() and starting.exception() is None:
            await _bounded_close(starting.result().stop)
            return
        # Playwright 1.63's public __aexit__ permanently marks the manager
        # stopped before it accesses the driver pipe. A failed OS spawn has
        # no pipe to close; calling __aexit__ would mask the original error.
        if transport is None or getattr(transport, "_output", None) is not None:
            try:
                await _bounded_close(lambda: manager.__aexit__(None, None, None))
            finally:
                if not starting.done():
                    starting.cancel()
                    await asyncio.gather(starting, return_exceptions=True)

    async def stop_driver():
        if not starting.done():
            await asyncio.wait({starting}, timeout=_CLOSE_SECONDS)
        transport = getattr(getattr(manager, "_connection", None), "_transport", None)
        # When the OS spawn is pending, the event loop and slot must outlive
        # the spawn. Its pipe becomes closable before the protocol handshake.
        while transport is not None and not starting.done() and getattr(transport, "_output", None) is None:
            await asyncio.wait({starting}, timeout=0.05)
        await finish(transport)

    stack.push_async_callback(stop_driver)
    return await asyncio.shield(starting)


async def _bounded_close(callback):
    # A stalled browser close must leave the driver its own time to shut down.
    with anyio.fail_after(_CLOSE_SECONDS, shield=True):
        await callback()


class LiveNavigation:
    """An async, single-use viewport owned by an eligible Python ResearchFlow."""

    def __init__(self, flow: ResearchFlow, handle: str):
        self._flow = flow
        self._handle = handle
        self._lock = asyncio.Lock()
        self._stack = None
        self._page = None
        self._watcher = None
        self._used = False
        self._actions = {}
        self._idle_until = self._end = 0.0

    async def __aenter__(self):
        async with self._lock:
            if self._used:
                raise RuntimeError("Live viewport already used")
            self._used = True
            item = self._flow._capture(self._handle)
            settings = egress_policy.browser_fetch_settings()
            if settings["mode"] == "off":
                raise browser_fetch.BrowserFetchUnavailable("Browser reads are off")
            markup = _markup(item)
            if not _SLOTS.acquire(blocking=False):
                raise browser_fetch.BrowserFetchUnavailable("Live viewport limit reached")
            self._stack = AsyncExitStack()
            self._stack.callback(_SLOTS.release)
            try:
                browser_fetch._take_rate_slot(settings["max_per_minute"])
                async with asyncio.timeout(_START_SECONDS):
                    self._page = await _open_page(self._stack, markup, settings)
                self._end = time.monotonic() + _LIFETIME
                self._idle_until = time.monotonic() + _IDLE
                self._flow._capture(self._handle, renew=False)
                self._watcher = asyncio.create_task(self._watch())
            except BaseException:
                await self._close_locked()
                raise
            return self

    async def __aexit__(self, *exc):
        await self.close()

    async def _close_locked(self):
        watcher, self._watcher = self._watcher, None
        if watcher and watcher is not asyncio.current_task():
            watcher.cancel()
        self._page = None
        self._actions.clear()
        stack, self._stack = self._stack, None
        if stack:
            with anyio.CancelScope(shield=True):
                # Task.cancel() may also arrive directly during browser.close().
                # Keep the slot and wait for teardown before propagating it.
                cleanup = asyncio.create_task(stack.aclose())
                cancelled = None
                while not cleanup.done():
                    try:
                        await asyncio.shield(cleanup)
                    except asyncio.CancelledError as exc:
                        cancelled = exc
                cleanup.result()
                if cancelled is not None:
                    raise cancelled

    async def close(self):
        with anyio.CancelScope(shield=True):
            async with self._lock:
                await self._close_locked()

    def _check(self):
        if self._page is None or time.monotonic() >= min(self._end, self._idle_until):
            raise SnapshotUnavailable("Live viewport unavailable")
        return self._flow._capture(self._handle, renew=False)

    async def _watch(self):
        # Release an idle browser even if the host never requests another view.
        try:
            while True:
                await asyncio.sleep(0.25)
                async with self._lock:
                    try:
                        self._check()
                    except SnapshotUnavailable:
                        await self._close_locked()
                        return
        finally:
            # An event loop shutting down can cancel the watcher directly.
            if self._watcher is asyncio.current_task():
                await self.close()

    async def view(self) -> Viewport:
        """Read viewport text and issue a new revision of opaque controls."""
        return await self._run(None)

    async def select(self, control_id: str) -> Viewport:
        """Apply one host-issued action from the last revision."""
        if not isinstance(control_id, str):
            raise ValueError("Expected a viewport control ID")
        return await self._run(control_id)

    async def _run(self, control_id):
        async with self._lock:
            try:
                item = self._check()
                if egress_policy.browser_fetch_settings()["mode"] == "off":
                    raise browser_fetch.BrowserFetchUnavailable("Browser reads are off")
            except BaseException:
                await self._close_locked()
                raise
            if control_id is not None and control_id not in self._actions:
                raise KeyError("Unknown or stale viewport control")
            try:
                async with asyncio.timeout(10):
                    if control_id is not None:
                        applied = await self._page.evaluate(live_viewport.APPLY, self._actions[control_id])
                        if not applied:
                            raise RuntimeError("Viewport control changed")
                    # Recompute visibility after scroll and disclosure reflow.
                    await self._page.evaluate(
                        "(a) => document.querySelectorAll('['+a+']').forEach(e=>e.removeAttribute(a))",
                        hidden_text.BROWSER_ATTR)
                    await self._page.evaluate(hidden_text.BROWSER_SCRIPT, hidden_text.BROWSER_ATTR)
                    state = await self._page.evaluate(live_viewport.INVENTORY)
                revision = secrets.token_urlsafe(16)
                actions, controls, lines = {}, [], []
                for i, action in enumerate(state["actions"]):
                    token = f"{revision}.{i}"
                    kind = action["kind"]
                    actions[token] = [kind, action["index"]]
                    controls.append(Control(token, kind))
                    lines.append(f"{token} {kind} — {action['label']}")
                clipped = state["clipped"] or state["actionsClipped"]
                body = state["text"] + "\n\nViewport controls\n" + "\n".join(lines)
                content = _evidence(body, item.url, "live_navigation", item.initial_scan,
                                    complete=not clipped)
                self._check()
                self._flow._capture(self._handle)
                self._idle_until = time.monotonic() + _IDLE
                self._actions = actions
                return Viewport(revision, content, tuple(controls), item.captured_at, clipped)
            except BaseException:
                await self._close_locked()
                raise
