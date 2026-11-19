"""Exercise the registered host-only tools against a synthetic public origin."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import anyio
import httpx
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from siftfetch import egress_policy, fetcher, host_flow, research_flow
from siftfetch.host_flow_tools import register_tools
from siftfetch.research_flow import ResearchFlow
from test_research_flow import public_page


@pytest.fixture
def endpoint():
    with ResearchFlow() as flow:
        server = MCPServer("synthetic-host-flow")
        register_tools(server, flow)

        def call(name, **args):
            result = anyio.run(server.call_tool, name, args)
            assert not result.is_error
            return json.loads(result.content[0].text)

        yield call


def test_view_sizes_marked_source_and_repeat_release(endpoint, public_page):
    origin, seen = public_page
    first = endpoint("open_page", url=origin + "/source")
    handle = first["handle"]
    assert handle and first["status"] == "ok"
    sizes = endpoint("page_sizes", handle=handle, max_chars=1500)["sizes"]
    for view, size in sizes.items():
        page = endpoint("read_page", handle=handle, view=view, max_chars=1500)
        assert page["captured_at"] == first["captured_at"] and page["handle"] == handle
        assert page["size_bytes"] == size == len(page["content"].encode("utf-8"))
        assert page["content"].startswith("[UNTRUSTED WEB CONTENT")
        if view == "source":
            assert "&lt;script&gt;" in page["content"]
    assert endpoint("release_page", handle=handle) == endpoint("release_page", handle=handle)
    assert endpoint("read_page", handle=handle) == {"status": "unavailable"}
    assert endpoint("page_sizes", handle=handle) == {"status": "unavailable"}
    assert seen == ["/source"]


def test_only_an_eligible_read_is_retained(endpoint, public_page):
    origin, seen = public_page
    old = endpoint("open_page", url=origin + "/article")["handle"]
    private = endpoint("open_page", url=origin + "/no-store")
    assert private["status"] == "call_only" and private["handle"] is None
    assert "Edition 2" in private["content"] and "[UNTRUSTED WEB CONTENT" in private["content"]
    assert endpoint("read_page", handle=old)["status"] == "unavailable"
    assert seen == ["/article", "/no-store"]


def test_expired_never_refetches(endpoint, public_page, monkeypatch):
    origin, seen = public_page
    monkeypatch.setattr(research_flow, "_IDLE_SECONDS", 0)
    handle = endpoint("open_page", url=origin + "/article")["handle"]
    assert endpoint("read_page", handle=handle) == endpoint("page_sizes", handle=handle) == {
        "status": "unavailable"}
    assert seen == ["/article"]


def test_old_release_and_concurrent_open_cannot_drop_replacement(endpoint, public_page):
    origin, seen = public_page
    old = endpoint("open_page", url=origin + "/article")["handle"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        opening = pool.submit(endpoint, "open_page", url=origin + "/source")
        releasing = pool.submit(endpoint, "release_page", handle=old)
        assert releasing.result()["status"] == "released"
        new = opening.result()["handle"]
    assert endpoint("read_page", handle=new)["status"] == "ok"
    assert endpoint("release_page", handle="unknown")["status"] == "released"
    assert endpoint("read_page", handle=new)["status"] == "ok"
    assert seen == ["/article", "/source"]


def test_outbound_policy_applies_to_open(endpoint, public_page):
    origin, seen = public_page
    with pytest.raises(ToolError) as exc:
        endpoint("open_page", url=origin + "/blocked-hop")
    assert isinstance(exc.value.__cause__, egress_policy.EgressDenied)
    assert seen == ["/blocked-hop"]


@pytest.mark.parametrize("value", [0, -1, 30001, True])
def test_renderer_bounds_enforced_for_read_and_size(endpoint, public_page, value):
    for tool in ("read_page", "page_sizes"):
        with pytest.raises(ToolError):
            endpoint(tool, handle="unknown", max_chars=value)
    assert public_page[1] == []


@pytest.mark.parametrize("failure,expected", [
    ("http", {"status": "http_error", "content": "Fetch failed (http_error): HTTP 502 Bad Gateway."}),
    ("transport", {"status": "network_error", "content": "Fetch failed (network_error): connection failed."}),
])
def test_safe_errors_over_host_connection(public_page, monkeypatch, failure, expected):
    origin, _ = public_page
    def respond(transport, request):
        if failure == "http":
            return httpx.Response(502, extensions={"reason_phrase": b"synthetic remote reason"},
                                  stream=httpx.ByteStream(b"synthetic remote body"))
        raise httpx.ConnectError("synthetic remote diagnostic", request=request)

    monkeypatch.setattr(fetcher._PinnedTransport, "handle_request", respond)
    async def scenario():
        async with host_flow.open_host_flow() as client:
            result = await client.call_tool("open_page", {"url": origin + "/synthetic-path?key=abcdef"})
            assert not result.is_error and json.loads(result.content[0].text) == expected
            for field in ("synthetic", "abcdef", origin):
                assert field not in str(result)
    anyio.run(scenario)


def test_inflight_private_response_never_survives_host_teardown(public_page, monkeypatch):
    origin, _ = public_page
    started, finish, drained = threading.Event(), threading.Event(), threading.Event()
    class PrivateStream(httpx.SyncByteStream):
        def __iter__(self):
            started.set()
            assert finish.wait(5)
            yield b"<main>private fixture</main>"
        def close(self):
            drained.set()
    def respond(transport, request):
        return httpx.Response(200, headers={"Content-Type": "text/html", "Cache-Control": "private"},
                              stream=PrivateStream())
    monkeypatch.setattr(fetcher._PinnedTransport, "handle_request", respond)

    async def worker():
        async with host_flow.open_host_flow() as client:
            await client.call_tool("open_page", {"url": origin + "/private"})

    async def scenario():
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(worker)
            try:
                assert await anyio.to_thread.run_sync(started.wait, 5)
                tasks.cancel_scope.cancel()
            finally:
                finish.set()
        assert drained.is_set() and not research_flow._captures
    anyio.run(scenario)
