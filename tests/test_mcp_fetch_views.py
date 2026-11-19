import json

import anyio
import pytest

from siftfetch import egress_policy, research_flow, server
from test_research_flow import public_page
from test_reviewed_hook import invoke


def test_same_capture_on_wire(public_page, monkeypatch):
    origin, seen = public_page
    marker = "synthetic-internal-handle"
    monkeypatch.setattr(research_flow.secrets, "token_urlsafe", lambda _: marker)
    result = anyio.run(server.mcp.call_tool, "fetch_page_views", {
        "url": origin + "/source", "views": ["full", "source"], "include_sizes": True})
    assert not result.is_error
    payload = json.loads(result.content[0].text)
    assert set(payload) == {"status", "captured_at", "views", "sizes"}
    assert payload["status"] == "ok" and payload["captured_at"]
    assert set(payload["views"]) == {"full", "source"}
    assert set(payload["sizes"]) == {"auto", "readability", "full", "raw", "source"}
    for view, entry in payload["views"].items():
        assert entry["size_bytes"] == len(entry["content"].encode()) == payload["sizes"][view]
        assert entry["content"].startswith("[UNTRUSTED WEB CONTENT") and entry["truncated"] is False
        assert origin in entry["content"] and "Edition 1" in entry["content"]
    assert "unique_source_text" not in payload["views"]["full"]["content"]
    assert "&lt;script&gt;" in payload["views"]["source"]["content"]
    assert marker not in str(result)
    assert seen == ["/source"] and not research_flow._captures


def test_size_only_and_call_only_reads(public_page):
    origin, seen = public_page
    catalog = anyio.run(server.fetch_page_views, origin + "/article", [], True)
    assert catalog["status"] == "ok" and not catalog["views"]
    assert len(catalog["sizes"]) == 5
    fallback = anyio.run(server.fetch_page_views, origin + "/no-store", ["source"], True)
    assert fallback["status"] == "call_only" and fallback["captured_at"] is None
    assert set(fallback["views"]) == {"auto"} and "Edition 2" in fallback["views"]["auto"]["content"]
    size_only = anyio.run(server.fetch_page_views, origin + "/no-store", [], True)
    assert not size_only["views"] and set(size_only["sizes"]) == {"auto"}
    assert seen == ["/article", "/no-store", "/no-store"]


def test_eviction_returns_available_read_without_retry(public_page, monkeypatch):
    origin, seen = public_page
    read = research_flow.ResearchFlow.read
    def evict(flow, *args, **kwargs):
        flow.release()
        return read(flow, *args, **kwargs)
    monkeypatch.setattr(research_flow.ResearchFlow, "read", evict)
    result = anyio.run(server.fetch_page_views, origin + "/article", ["source"], True)
    assert result["status"] == "capture_unavailable"
    assert set(result["views"]) == set(result["sizes"]) == {"auto"}
    assert seen == ["/article"] and not research_flow._captures


@pytest.mark.parametrize("views", [[], ["auto"] * 6, ["full", "full"], ["other"]])
def test_rejects_bad_options_before_fetch(public_page, views):
    origin, seen = public_page
    with pytest.raises(ValueError):
        anyio.run(server.fetch_page_views, origin, views)
    assert seen == []


def test_guard_denies_redirect_before_target(public_page):
    origin, seen = public_page
    with pytest.raises(egress_policy.EgressDenied) as exc:
        anyio.run(server.fetch_page_views, origin + "/blocked-hop", ["source"])
    assert exc.value.decision.reason_code == "blocked_domain"
    assert seen == ["/blocked-hop"]


def test_transport_denies_synthetic_identifier_without_hook(public_page, tmp_path):
    origin, seen = public_page
    identifier = "private-fixture@mail.example"
    (tmp_path / "identifiers.json").write_text(json.dumps({"version": 1, "values": [
        {"label": "fixture", "kind": "email", "value": identifier, "class": "exact"}]}))
    with pytest.raises(egress_policy.EgressDenied) as exc:
        anyio.run(server.fetch_page_views, origin + "/page?q=" + identifier, ["full"])
    assert exc.value.decision.reason_code == "protected_value"
    assert seen == []


def test_exception_releases_flow(public_page, monkeypatch):
    origin, seen = public_page
    def failed_render(*args, **kwargs):
        raise RuntimeError("synthetic render error")
    monkeypatch.setattr(research_flow.ResearchFlow, "read", failed_render)
    with pytest.raises(RuntimeError, match="synthetic render error"):
        anyio.run(server.fetch_page_views, origin + "/article", ["source"])
    assert seen == ["/article"] and not research_flow._captures


@pytest.mark.parametrize("unattended,expected", [(True, "deny"), (False, "ask")])
def test_hook_checks_protected_input(invoke, unattended, expected):
    decision = invoke("mcp__siftfetch__fetch_page_views", url="https://docs.example/?id=synthetic@mail.test",
                      views=["source"], unattended=unattended)
    assert decision["permissionDecision"] == expected
