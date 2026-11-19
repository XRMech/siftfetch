import json

import httpx
import pytest

from siftfetch import egress_policy, fetcher
from siftfetch.pagination import follow_next, pagination_inventory
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    (tmp_path / "identifiers.json").write_text('{"version":1,"values":[]}')
    seen, resolved, pages = [], [], {}
    def resolve(host, port):
        resolved.append((host, port))
        return ["93.184.216.34"]
    monkeypatch.setattr(egress_policy, "resolve_public", resolve)
    def route(transport, request):
        seen.append(request)
        assert request.method == "GET"
        assert "cookie" not in request.headers and "authorization" not in request.headers
        status, headers, html = pages[request.url.path]
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(html.encode()))
    monkeypatch.setattr(fetcher._PinnedTransport, "handle_request", route)
    with ResearchFlow() as flow:
        yield flow, seen, resolved, pages


def html(body, **headers):
    return (200, {"Cache-Control": "public", "Content-Type": "text/html", **headers},
            "<main>" + "Field notes. " * 80 + body + "</main>")


def test_navigation_chain_uses_selected_link_and_replaces_capture(site):
    flow, seen, resolved, pages = site
    pages["/one"] = html("<base href='/reports/'><link rel=next href='two'>"
                         "<a rel=next href='two'>more</a><a href='other'>Next</a>")
    pages["/reports/two"] = html("Station 2. <a rel='NEXT nofollow' href='three?page=3'>Read more</a>")
    pages["/reports/three"] = html("<p>Third station</p>")
    first = flow.fetch("https://pages.example/one")
    links = pagination_inventory(flow, first.handle)
    assert len(links.ids) == 1 and "/reports/two" in links.content and len(seen) == 1
    with ResearchFlow() as other, pytest.raises(SnapshotUnavailable):
        follow_next(other, first.handle, links.ids[0])
    with pytest.raises(KeyError):
        follow_next(flow, first.handle, "https://pages.example/reports/two")
    second = follow_next(flow, first.handle, links.ids[0])
    assert second.handle and second.handle != first.handle
    assert "Station 2" in second.content and "[UNTRUSTED WEB CONTENT" in second.content
    assert "source=https://pages.example/reports/two" in second.content
    with pytest.raises(SnapshotUnavailable):
        follow_next(flow, first.handle, links.ids[0])
    current = pagination_inventory(flow, second.handle)
    with pytest.raises(KeyError):
        follow_next(flow, second.handle, links.ids[0])
    third = follow_next(flow, second.handle, current.ids[0])
    assert third.handle is None and "Third station" in third.content
    assert seen[-1].url.query == b"page=3" and len(seen) == len(resolved) == 3


@pytest.mark.parametrize("bad", ["https://other.example/next", "https://pages.example:444/next",
                                  "http://pages.example/next", "https://user@pages.example/next",
                                  "/next?token=secret", "/next?page=2&page=3"])
def test_off_scope_redirect_never_resolves_or_connects(site, bad):
    flow, seen, resolved, pages = site
    pages["/one"] = html("<a rel=next href='/hop'>Page 2</a>")
    pages["/hop"] = (302, {"Location": bad, "Set-Cookie": "s=test"}, "")
    first = flow.fetch("https://pages.example/one")
    links = pagination_inventory(flow, first.handle)
    with pytest.raises(ValueError, match="same-origin"):
        follow_next(flow, first.handle, links.ids[0])
    assert len(seen) == len(resolved) == 2
    assert pagination_inventory(flow, first.handle).ids == links.ids


def test_same_origin_redirect_is_checked_and_never_replays_cookies(site):
    flow, seen, _, pages = site
    pages["/one"] = html("<a rel='next' href='/hop'>Page 2</a>")
    pages["/hop"] = (302, {"Location": "/target", "Set-Cookie": "s=test"}, "")
    pages["/target"] = html("<p>Follow-up evidence</p>")
    first = flow.fetch("https://pages.example/one")
    links = pagination_inventory(flow, first.handle)
    result = follow_next(flow, first.handle, links.ids[0])
    assert not result.handle and "source=https://pages.example/target" in result.content
    assert "Follow-up evidence" in result.content and len(seen) == 3


def test_redirect_policy_and_rebinding(site, monkeypatch, tmp_path):
    flow, seen, _, pages = site
    pages["/one"] = html("<a rel='next' href='/hop'>Page 2</a>")
    pages["/hop"] = (302, {"Location": "/synthetic-private-value"}, "")
    first = flow.fetch("https://pages.example/one")
    key, = pagination_inventory(flow, first.handle).ids
    (tmp_path / "identifiers.json").write_text(json.dumps({"version": 1, "values": [
        {"label": "fixture", "kind": "text", "value": "synthetic-private-value", "class": "exact"}]}))
    monkeypatch.setattr(egress_policy, "_cached", None)
    with pytest.raises(egress_policy.EgressDenied):
        follow_next(flow, first.handle, key)
    assert [r.url.path for r in seen] == ["/one", "/hop"]
    monkeypatch.setattr(egress_policy, "resolve_public", lambda *_: ["127.0.0.1"])
    with pytest.raises(egress_policy.EgressDenied):
        follow_next(flow, first.handle, key)
    assert len(seen) == 2


def test_ineligible_markup_never_makes_a_request(site):
    flow, seen, _, pages = site
    pages["/one"] = html("""<a href='/arbitrary'>Next</a>
        <a rel=next href='https://user@pages.example/deep'>a</a>
        <a rel=next href='//other.example'>b</a>
        <form><a rel=next href='/side-effect'>c</a></form>
        <a rel=next href='/page?session=42'>d</a>
        <a rel=next href='javascript:void(0)'>e</a>
        <template><a rel=next href='/template'>f</a></template>
        <a rel=next target='_blank' href='/popup'>x</a><a rel=next ping='/ping' href='/pinged'>y</a>
        <a rel=next onclick='return false' href='/scripted'>z</a>
        <a rel=next download href='/download'>g</a>""")
    first = flow.fetch("https://pages.example/one")
    assert pagination_inventory(flow, first.handle).ids == ()
    assert len(seen) == 1


def test_inventory_bound_and_ineligible_result(site):
    flow, seen, _, pages = site
    pages["/one"] = html("".join(f"<a rel=next href='/r/{i}'>Next</a>" for i in range(33)))
    pages["/r/0"] = html("private fixture", **{"Cache-Control": "no-store"})
    first = flow.fetch("https://pages.example/one")
    inventory = pagination_inventory(flow, first.handle)
    assert len(inventory.ids) == 32 and inventory.truncated and "complete=false" in inventory.content
    result = follow_next(flow, first.handle, inventory.ids[0])
    assert "private fixture" in result.content and result.handle is None and len(seen) == 2
    with pytest.raises(SnapshotUnavailable):
        pagination_inventory(flow, first.handle)


@pytest.mark.parametrize("headers", [
    {"Content-Type": "image/png"}, {"Content-Disposition": "attachment"},
    {"Content-Range": "bytes 0-3/10"}])
def test_unsupported_response_keeps_original_capture(site, headers):
    flow, _, _, pages = site
    pages["/one"] = html("<link rel='next' href='/next'>")
    pages["/next"] = html("partial evidence", **headers)
    first = flow.fetch("https://pages.example/one")
    links = pagination_inventory(flow, first.handle)
    with pytest.raises(ValueError, match="complete HTML"):
        follow_next(flow, first.handle, links.ids[0])
    assert pagination_inventory(flow, first.handle).ids == links.ids
