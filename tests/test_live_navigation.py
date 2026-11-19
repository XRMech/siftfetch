import asyncio
import os
import socket
import sys
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import anyio
import httpx
import pytest

from siftfetch import browser_fetch, egress_policy, live_navigation as nav
from siftfetch import live_viewport, tools
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable


@pytest.fixture
def page_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    (tmp_path / "identifiers.json").write_text('{"version":1,"values":[]}')
    (tmp_path / "config.json").write_text('{"browser_fetch":{"mode":"on-wall","max_per_minute":60}}')
    monkeypatch.setattr(browser_fetch, "_reads", browser_fetch.collections.deque())
    urls = []

    def start(html):
        def fetch(url, **kwargs):
            urls.append(url)
            return httpx.Response(200, request=httpx.Request("GET", url),
                                  headers={"Cache-Control": "public", "Content-Type": "text/html"},
                                  content=html.encode(), extensions={"siftfetch_public_direct": True})
        monkeypatch.setattr(tools, "fetch", fetch)
        flow = ResearchFlow()
        first = flow.fetch("https://fixture.example/station")
        assert first.handle
        return flow, first.handle
    return start, urls


class StubPage:
    def __init__(self):
        self.applied = []
        self.closed = threading.Event()

    async def evaluate(self, code, arg=None):
        if code == live_viewport.APPLY:
            self.applied.append(arg)
            return True
        if code == live_viewport.INVENTORY:
            return {"text": "Field reading: 42", "actions": [
                {"kind": "next", "label": "Next screen", "index": 0}],
                    "clipped": False, "actionsClipped": False}


def test_controls_release_and_isolation(page_flow, monkeypatch):
    start, urls = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    pages = []
    async def launch(stack, markup, settings):
        page = StubPage()
        pages.append(page)
        stack.callback(page.closed.set)
        return page
    monkeypatch.setattr(nav, "_open_page", launch)

    async def run():
        async with nav.LiveNavigation(flow, handle) as first, nav.LiveNavigation(flow, handle) as other:
            view = await first.view()
            assert "Field reading" in view.content and "[UNTRUSTED WEB CONTENT" in view.content
            assert "https://fixture.example/station" in view.content
            await other.view()
            with pytest.raises(KeyError):
                await other.select(view.controls[0].id)
            second = await first.select(view.controls[0].id)
            assert second.revision != view.revision and pages[0].applied == [["next", 0]]
            with pytest.raises(KeyError):
                await first.select(view.controls[0].id)
            flow.release()
            await asyncio.sleep(0.4)
            assert all(p.closed.is_set() for p in pages)
            with pytest.raises(SnapshotUnavailable):
                await first.view()
    asyncio.run(run())
    assert urls == ["https://fixture.example/station"]
    flow.close()


def test_idle_expiry_and_failure(page_flow, monkeypatch):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    page = StubPage()
    async def launch(stack, markup, settings):
        stack.callback(page.closed.set)
        return page
    monkeypatch.setattr(nav, "_open_page", launch)
    monkeypatch.setattr(nav, "_IDLE", 0.05)
    async def run():
        async with nav.LiveNavigation(flow, handle) as live:
            await live.view()
            await asyncio.sleep(0.35)
            assert page.closed.is_set()
            with pytest.raises(SnapshotUnavailable):
                await live.view()
        page.closed.clear()
        async with nav.LiveNavigation(flow, handle) as live:
            async def fail(*args):
                raise RuntimeError("synthetic render failure")
            page.evaluate = fail
            with pytest.raises(RuntimeError, match="synthetic"):
                await live.view()
            assert page.closed.is_set()
    asyncio.run(run())
    flow.close()


def test_disabled_and_ineligible(page_flow, monkeypatch):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    monkeypatch.setattr(egress_policy, "browser_fetch_settings", lambda: {"mode": "off"})
    async def run():
        with pytest.raises(browser_fetch.BrowserFetchUnavailable):
            async with nav.LiveNavigation(flow, handle):
                pytest.fail("disabled renderer opened")
        with ResearchFlow() as unrelated, pytest.raises(SnapshotUnavailable):
            async with nav.LiveNavigation(unrelated, handle):
                pytest.fail("foreign handle opened")
    asyncio.run(run())
    flow.close()


def test_backend_proxy_denies_plain_and_connect(monkeypatch):
    upstream = []
    handled = threading.Event()
    handle = nav.egress_proxy._Handler.handle

    def observe(handler):
        handle(handler)
        handled.set()

    def unexpected(self, url, port):
        upstream.append((url, port))
        raise AssertionError("An offline proxy attempted an upstream connection")
    monkeypatch.setattr(nav.egress_proxy._Handler, "handle", observe)
    monkeypatch.setattr(nav.egress_proxy._Handler, "_connect", unexpected)
    with nav.egress_proxy.EgressProxy(offline=True) as proxy:
        for request in (b"GET http://127.0.0.1/ HTTP/1.1",
                        b"CONNECT 127.0.0.1:443 HTTP/1.1"):
            handled.clear()
            with socket.create_connection(("127.0.0.1", proxy.port), timeout=2) as sock:
                try:
                    sock.sendall(request + b"\r\nHost: 127.0.0.1\r\n\r\n")
                    assert sock.recv(1) == b""
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass  # Closing before reading may abort/reset the accepted socket.
            assert handled.wait(timeout=2)
        assert not proxy.connected and not upstream


def test_resources_close_on_owner_cancellation(page_flow, monkeypatch):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    page = StubPage()
    async def launch(stack, markup, settings):
        stack.callback(page.closed.set)
        return page
    monkeypatch.setattr(nav, "_open_page", launch)
    async def run():
        ready = asyncio.Event()
        async def owner():
            async with nav.LiveNavigation(flow, handle) as live:
                await live.view()
                ready.set()
                await asyncio.Event().wait()
        task = asyncio.create_task(owner())
        await asyncio.wait_for(ready.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert page.closed.is_set()
    asyncio.run(run())
    flow.close()


@pytest.mark.parametrize("phase", ["launch", "view", "body"])
def test_level_cancellation_finishes_async_cleanup_and_releases_slot(page_flow, monkeypatch, phase):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(nav, "_SLOTS", slots)
    closed = []
    async def run():
        ready = anyio.Event()
        async def cleanup(name):
            # Level cancellation would interrupt both checkpoints without a shield.
            await anyio.sleep(0)
            await anyio.sleep(0)
            assert not slots.acquire(blocking=False)
            closed.append(name)

        async def wait(*args):
            ready.set()
            await anyio.sleep_forever()

        async def launch(stack, markup, settings):
            stack.push_async_callback(cleanup, "driver")
            if phase == "launch":
                await wait()
            stack.push_async_callback(cleanup, "browser")
            page = StubPage()
            if phase == "view":
                page.evaluate = wait
            return page
        monkeypatch.setattr(nav, "_open_page", launch)
        async def owner():
            async with nav.LiveNavigation(flow, handle) as live:
                if phase == "view":
                    await live.view()
                else:
                    await wait()
        async with anyio.create_task_group() as group:
            group.start_soon(owner)
            await ready.wait()
            group.cancel_scope.cancel()
        assert closed == (["driver"] if phase == "launch" else ["browser", "driver"])
        assert slots.acquire(blocking=False)
        slots.release()
    try:
        anyio.run(run)
    finally:
        flow.close()


def test_hung_browser_close_leaves_driver_budget_and_releases_slot(page_flow, monkeypatch):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(nav, "_SLOTS", slots)
    monkeypatch.setattr(nav, "_CLOSE_SECONDS", 0.05)
    drained = []
    async def driver_close():
        await anyio.sleep(0)
        drained.append("driver")
    async def launch(stack, markup, settings):
        stack.push_async_callback(nav._bounded_close, driver_close)
        stack.push_async_callback(nav._bounded_close, anyio.sleep_forever)
        return StubPage()
    monkeypatch.setattr(nav, "_open_page", launch)
    async def run():
        with pytest.raises(TimeoutError), anyio.fail_after(2):
            async with nav.LiveNavigation(flow, handle):
                pass
        assert drained == ["driver"] and slots.acquire(blocking=False)
        slots.release()
    try:
        anyio.run(run)
    finally:
        flow.close()


def test_task_cancel_during_browser_close_waits_for_async_teardown(page_flow, monkeypatch):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(nav, "_SLOTS", slots)
    async def run():
        closing, finish, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def browser_close():
            closing.set()
            await finish.wait()
            closed.set()
        async def launch(stack, markup, settings):
            stack.push_async_callback(browser_close)
            return StubPage()
        monkeypatch.setattr(nav, "_open_page", launch)
        async def owner():
            async with nav.LiveNavigation(flow, handle):
                pass
        task = asyncio.create_task(owner())
        await asyncio.wait_for(closing.wait(), timeout=2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not slots.acquire(blocking=False)
        finish.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        assert closed.is_set() and slots.acquire(blocking=False)
        slots.release()
    try:
        asyncio.run(run())
    finally:
        flow.close()


@pytest.mark.parametrize("interruption", ["cancel", "timeout", "failed", "stalled"])
def test_driver_acquisition_owns_partial_transport(page_flow, monkeypatch, interruption):
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(nav, "_SLOTS", slots)
    monkeypatch.setattr(nav, "_CLOSE_SECONDS", 0.15)

    async def run():
        entered, ready = asyncio.Event(), asyncio.Event()
        drained = []
        class Manager:
            async def start(self):
                entered.set()
                await ready.wait()
                if interruption == "failed":
                    raise RuntimeError("synthetic readiness failure")
                return SimpleNamespace(stop=self.stop)

            async def stop(self):
                await asyncio.sleep(0)
                assert not slots.acquire(blocking=False)
                drained.append("ready")

            async def __aexit__(self, *exc):
                await asyncio.sleep(0)
                assert not slots.acquire(blocking=False)
                drained.append("partial")

        api = SimpleNamespace(async_playwright=Manager)
        monkeypatch.setitem(sys.modules, "playwright.async_api", api)
        timeout = asyncio.timeout(None)
        async def owner():
            async with timeout, nav.LiveNavigation(flow, handle):
                pytest.fail("A cancelled or failed startup launched the browser")
        task = asyncio.create_task(owner())
        await asyncio.wait_for(entered.wait(), timeout=2)
        if interruption == "failed":
            ready.set()
        else:
            if interruption == "timeout":
                timeout.reschedule(asyncio.get_running_loop().time())
            else:
                task.cancel()
            await asyncio.sleep(0.01)
            assert not task.done() and not slots.acquire(blocking=False)
            if interruption != "stalled":
                ready.set()
        expected = {"timeout": TimeoutError, "failed": RuntimeError}.get(interruption, asyncio.CancelledError)
        with pytest.raises(expected):
            await asyncio.wait_for(task, timeout=2)
        assert drained == (["partial"] if interruption in {"stalled", "failed"} else ["ready"])
        assert slots.acquire(blocking=False)
        slots.release()
    try:
        asyncio.run(run())
    finally:
        flow.close()


@pytest.mark.parametrize("case", ["failure", "cancel", "mcp-timeout"])
def test_real_playwright_transport_spawn_failure_or_late_pipe(page_flow, monkeypatch, case):
    pytest.importorskip("playwright.async_api")
    from playwright._impl import _transport
    start, _ = page_flow
    flow, handle = start("<main>" + "Station report. " * 80 + "</main>")
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(nav, "_SLOTS", slots)
    monkeypatch.setattr(nav, "_CLOSE_SECONDS", 0.03)
    monkeypatch.setattr(_transport, "get_driver_env", lambda: {})

    async def run():
        spawning, release_spawn = asyncio.Event(), asyncio.Event()
        class InMemoryProcess:
            stdin = None
            closed = False
            def write(self, data):
                pass
            def close(self):
                self.closed = True
                self.stdout.feed_eof()
            async def communicate(self):
                return b"", b""
        proc = InMemoryProcess()
        proc.stdin = proc
        async def spawn(*args, **kwargs):
            proc.stdout = asyncio.StreamReader()
            if case == "mcp-timeout":
                await asyncio.sleep(0.12)
                assert not slots.acquire(blocking=False)
                return proc
            spawning.set()
            if case == "failure":
                raise FileNotFoundError("synthetic driver absent")
            await release_spawn.wait()
            return proc
        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        if case == "mcp-timeout":
            from siftfetch.mcp_navigation import navigate_once
            monkeypatch.setattr(nav, "_START_SECONDS", 0.02)
            with pytest.raises(TimeoutError):
                await asyncio.to_thread(navigate_once, "https://fixture.example/station", "viewport")
            assert proc.closed and slots.acquire(blocking=False)
            slots.release()
            return
        async def owner():
            async with nav.LiveNavigation(flow, handle):
                pytest.fail("A transport without a handshake cannot launch a browser")
        task = asyncio.create_task(owner())
        await asyncio.wait_for(spawning.wait(), timeout=2)
        if case == "failure":
            with pytest.raises(FileNotFoundError, match="synthetic driver absent"):
                await task
        else:
            task.cancel()
            await asyncio.sleep(0.07)
            assert not task.done() and not slots.acquire(blocking=False)
            release_spawn.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
            assert proc.closed
        assert slots.acquire(blocking=False)
        slots.release()
    try:
        asyncio.run(run())
    finally:
        flow.close()


@pytest.mark.skipif(os.environ.get("SIFTFETCH_BROWSER_TESTS") != "1",
                    reason="opt-in isolated Chromium viewport")
def test_chromium_disclosure_scroll_and_no_egress(page_flow):
    pytest.importorskip("playwright.async_api")
    start, urls = page_flow
    hits = []
    class Sink(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(204)
            self.end_headers()
        do_POST = do_GET
        def log_message(self, *args):
            pass
    with ThreadingHTTPServer(("127.0.0.1", 0), Sink) as sink:
        threading.Thread(target=sink.serve_forever, daemon=True).start()
        target = f"http://127.0.0.1:{sink.server_port}/sink"
        body = (f"<style>main {{background-image:url({target})}}</style><main>"
                f"<script>fetch('{target}')</script><a href='{target}'>Station</a>"
                "<details><summary>Read gauge</summary><p>GAUGE RELEASE 42</p></details>"
                "<button id='tab' role='tab' aria-controls='panel'>Rainfall</button>"
                "<div id='panel' role='tabpanel' aria-labelledby='tab' hidden>RAIN LEVEL 16</div>"
                "<div style='height:800px'>Field station report.</div>"
                "<p>LOWER STATION RECORD</p><p>" + "Measured sample. " * 80 + "</p></main>")
        flow, handle = start(body)
        async def run():
            async with nav.LiveNavigation(flow, handle) as live:
                first = await live.view()
                assert "GAUGE RELEASE" not in first.content
                second = await live.select(next(c.id for c in first.controls if c.kind == "details"))
                assert "GAUGE RELEASE 42" in second.content
                third = await live.select(next(c.id for c in second.controls if c.kind == "tab"))
                assert "RAIN LEVEL 16" in third.content
                fourth = await live.select(next(c.id for c in third.controls if c.kind == "next"))
                assert "LOWER STATION RECORD" in fourth.content
        try:
            asyncio.run(run())
        finally:
            flow.close()
            sink.shutdown()
    assert not hits and urls == ["https://fixture.example/station"]
