import json
import os
from types import SimpleNamespace

import anyio
import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from siftfetch import egress_policy, fetcher, mcp_navigation as nav
from test_reviewed_hook import invoke


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    (tmp_path / "identifiers.json").write_text('{"version":1,"values":[]}')
    monkeypatch.setattr(egress_policy, "resolve_public", lambda host, port: ["93.184.216.34"])
    pages, seen = {}, []

    def get(transport, request):
        assert request.method == "GET"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        seen.append(request.url.path)
        return httpx.Response(200, headers={"content-type": "text/html", "cache-control": "public"},
                              stream=httpx.ByteStream(("<main>" + "Field note. " * 80 +
                                                       pages[request.url.path] + "</main>").encode()))

    monkeypatch.setattr(fetcher._PinnedTransport, "handle_request", get)
    return pages, seen


URL = "https://pages.example/one"


def tool_call(**arguments):
    from siftfetch import server
    return anyio.run(server.mcp.call_tool, "navigate_page", {"url": URL, **arguments})


def test_registered_reads_pinned_next_and_rejects_changed_next(site):
    pages, seen = site
    pages.update({"/one": "<link rel=next href='/two'>", "/two": "<p>Second quarter result</p>"})
    response = tool_call(mode="next", selections=[1], expected_next_url="https://pages.example/two")
    assert not response.is_error
    result = json.loads(response.content[0].text)
    assert result["content"].startswith("[UNTRUSTED WEB CONTENT")
    assert "Second quarter result" in result["content"] and "handle" not in result
    with pytest.raises(ToolError) as mismatch:
        tool_call(mode="next", selections=[1], expected_next_url="https://pages.example/other")
    assert isinstance(mismatch.value.__cause__, ValueError)
    assert seen == ["/one", "/two", "/one"]


def test_registered_denies_protected_source_before_transport(site, tmp_path):
    protected = "synthetic-private-station"
    (tmp_path / "identifiers.json").write_text(json.dumps({"values": [
        {"label": "fixture", "kind": "text", "value": protected, "class": "exact"}]}))
    with pytest.raises(ToolError) as denied:
        tool_call(url=URL + "?q=" + protected, mode="panels")
    assert isinstance(denied.value.__cause__, egress_policy.EgressDenied)
    assert denied.value.__cause__.decision.reason_code == "protected_value" and site[1] == []


@pytest.mark.parametrize("headless,decision", [(True, "deny"), (False, "ask")])
def test_hook_covers_navigation(invoke, headless, decision):
    response = invoke("mcp__siftfetch__navigate_page", url=URL + "?q=synthetic@mail.test",
                      mode="panels", unattended=headless)
    assert response["permissionDecision"] == decision


@pytest.mark.skipif(os.environ.get("SIFTFETCH_BROWSER_TESTS") != "1",
                    reason="opt-in isolated Edge MCP viewport")
def test_registered_viewport_opens_real_disclosure(site, tmp_path):
    pytest.importorskip("playwright.async_api")
    pages, seen = site
    (tmp_path / "config.json").write_text('{"browser_fetch":{"browser":"msedge","mode":"on-wall"}}')
    pages["/one"] = "<details><summary>Gauge</summary><p>Hidden reading 42</p></details>"
    response = tool_call(mode="viewport", selections=[1])
    assert not response.is_error
    result = json.loads(response.content[0].text)
    assert result["content"].startswith("[UNTRUSTED WEB CONTENT")
    assert "Hidden reading 42" in result["content"] and seen == ["/one"]


def test_panel_evidence_and_flow_release(site):
    pages, seen = site
    pages["/one"] = "<details><summary>Observations</summary>Lunar sample</details>"
    inventory = nav.navigate_once(URL, "panels")
    assert inventory["control_count"] == 1 and "Observations" in inventory["content"]
    result = nav.navigate_once(URL, "panels", [1])
    evidence, = result["panels"]
    assert "Lunar sample" in evidence["content"] and "[UNTRUSTED WEB CONTENT" in evidence["content"]
    assert "handle" not in result and seen == ["/one", "/one"]


def test_next_verifies_current_destination_before_connecting(site):
    pages, seen = site
    pages["/one"] = "<a rel=next href='/two'>Next page</a>"
    assert "https://pages.example/two" in nav.navigate_once(URL, "next")["content"]
    pages["/one"] = "<a rel=next href='/replacement'>New page</a>"
    with pytest.raises(ValueError, match="did not match"):
        nav.navigate_once(URL, "next", [1], "https://pages.example/two")
    assert seen == ["/one", "/one"]
    pages["/replacement"] = "<p>Second page sample</p>"
    result = nav.navigate_once(URL, "next", [1], "https://pages.example/replacement")
    assert "[UNTRUSTED WEB CONTENT" in result["content"] and "Second page sample" in result["content"]
    assert seen[-2:] == ["/one", "/replacement"]


@pytest.mark.parametrize("mode,choices,url", [
    ("next", [1, 2], URL), ("next", [1], None), ("next", [], URL),
    ("panels", [1, 1], None), ("panels", [1, 2, 3, 4, 5], None),
    ("viewport", [65], None), ("viewport", [True], None), ("viewport", [0], None),
])
def test_invalid_navigation_performs_no_fetch(site, mode, choices, url):
    with pytest.raises(ValueError):
        nav.navigate_once(URL, mode, choices, url)
    assert site[1] == []


def test_viewport_uses_controls_from_latest_revision_and_closes(site, monkeypatch):
    pages, seen = site
    pages["/one"] = "Survey"
    actions = []

    class FakeViewport:
        def __init__(self, flow, handle):
            assert flow._capture(handle)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            actions.append("closed")

        async def view(self):
            return SimpleNamespace(content="marked evidence", truncated=False,
                                   controls=[SimpleNamespace(id=str(len(actions)))])

        async def select(self, key):
            actions.append(key)
            return await self.view()

    monkeypatch.setattr(nav, "LiveNavigation", FakeViewport)
    assert nav.navigate_once(URL, "viewport", [1, 1])["content"] == "marked evidence"
    assert actions == ["0", "1", "closed"] and seen == ["/one"]
    with pytest.raises(ValueError, match="unavailable"):
        nav.navigate_once(URL, "viewport", [2])
    assert actions[-1] == "closed"
