"""Tests for real-browser reads: settings gates and rate limit. No browser is launched."""

import json

import pytest

from siftfetch import browser_fetch as bf
from siftfetch import egress_policy as ep


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(
        json.dumps({"version": 1, "values": []}), encoding="utf-8")
    bf._reads.clear()

    def write(**browser_fetch):
        (tmp_path / "config.json").write_text(
            json.dumps({"browser_fetch": browser_fetch}), encoding="utf-8")
    return write


def test_off_by_default_wants_nothing(config):
    assert not bf.wanted("https://medium.com/x", walled=True)
    with pytest.raises(bf.BrowserFetchUnavailable, match="off"):
        bf.read_page("https://medium.com/x")


def test_on_wall_only_when_walled(config):
    config(mode="on-wall")
    assert bf.wanted("https://medium.com/x", walled=True)
    assert not bf.wanted("https://medium.com/x", walled=False)


def test_listed_sites_match_on_dot_boundaries(config):
    config(mode="always-for-listed", sites=["medium.com"])
    assert bf.wanted("https://blog.medium.com/x", walled=False)
    assert bf.wanted("https://medium.com/x", walled=False)
    assert not bf.wanted("https://notmedium.com/x", walled=False)
    assert bf.wanted("https://notmedium.com/x", walled=True)


def test_denied_page_is_never_opened(config):
    config(mode="on-wall")
    with pytest.raises(ep.EgressDenied):
        bf.read_page("http://127.0.0.1:9/x")
    assert not bf._reads  # no rate slot taken, no browser started


def test_rate_limit(config):
    for _ in range(3):
        bf._take_rate_slot(3)
    with pytest.raises(bf.BrowserFetchUnavailable, match="3 a minute"):
        bf._take_rate_slot(3)


@pytest.mark.parametrize("window, expect", [
    ("offscreen", "--window-position=-32000,-32000"),
    ("minimized", "--start-minimized"),
    ("visible", "--window-size=1280,900"),
])
def test_window_args(window, expect):
    assert expect in bf._window_args(window)


def _fake_playwright(monkeypatch, html_size, content="<html><body>ok</body></html>"):
    """A stand-in Playwright whose page reports ``html_size`` characters."""
    import sys
    import types
    calls = []

    class Error(Exception):
        pass

    class Page:
        url = "http://127.0.0.1:47700/p"

        def goto(self, *a, **k): pass
        def title(self): return "Page"
        def wait_for_load_state(self, *a, **k): pass

        def evaluate(self, script, *a):
            return html_size if "outerHTML.length" in script else None

        def content(self):
            calls.append("content")
            return content

    class Context:
        def route(self, *a): pass
        def route_web_socket(self, *a): pass
        def new_page(self): return Page()

    class Browser:
        def new_context(self, **k): return Context()
        def close(self): calls.append("closed")

    class PW:
        chromium = types.SimpleNamespace(launch=lambda **k: Browser())
        def __enter__(self): return self
        def __exit__(self, *a): return False

    module = types.ModuleType("playwright.sync_api")
    module.Error = Error
    module.sync_playwright = PW
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)
    return calls


def test_oversized_page_is_not_copied_out(config, monkeypatch):
    config(mode="on-wall")
    calls = _fake_playwright(monkeypatch, bf._MAX_HTML_CHARS + 1)
    with pytest.raises(bf.BrowserFetchUnavailable, match="MB of HTML"):
        bf.read_page("https://docs.example/p")
    assert "content" not in calls and "closed" in calls


def test_page_under_cap_is_read(config, monkeypatch):
    # Control: the same fake page under the cap comes back.
    config(mode="on-wall")
    calls = _fake_playwright(monkeypatch, 1_000)
    page = bf.read_page("https://docs.example/p")
    assert "ok" in page.html and calls == ["content", "closed"]


def test_page_that_grows_after_measuring_is_refused(config, monkeypatch):
    # Re-audit finding 7: a page whose scripts grow it after the first
    # measurement is caught on the bytes actually copied out.
    config(mode="on-wall")
    monkeypatch.setattr(bf, "_MAX_HTML_CHARS", 1_000)
    _fake_playwright(monkeypatch, 100, content="<p>" + "é" * 600 + "</p>")
    with pytest.raises(bf.BrowserFetchUnavailable, match="MB of HTML"):
        bf.read_page("https://docs.example/p")
