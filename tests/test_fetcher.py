"""Tests for the policy-checked fetcher: hops, cookies, pinning. No public network."""

import json
import threading
from pathlib import Path
import time
from http.cookiejar import Cookie, CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpcore
import httpx
import pytest

from siftfetch import egress_policy as ep
from siftfetch import fetcher

EMAIL = "pat.example@mailhost.test"


class _Handler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str | None]] = []
    redirect_to: str | None = None
    set_cookie: str | None = None
    files: dict[str, tuple[bytes, str, str | None]] = {}

    def do_GET(self):  # noqa: N802
        type(self).seen.append((self.path, self.headers.get("Cookie")))
        if self.path == "/slow-headers":
            # Header bytes dribbled out, each well inside the read timeout.
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                while True:
                    self.wfile.write(b"X-Pad: x\r\n")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                return
        if self.path == "/wall":
            body = b"<html><title>Just a moment...</title>cf-chl</html>"
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/drip":
            # An endless slow body: one small chunk at a time, never finished.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b"<p>more</p>")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                return
        if self.path.startswith("/hop") and type(self).redirect_to:
            self.send_response(302)
            self.send_header("Location", type(self).redirect_to)
            if type(self).set_cookie:
                self.send_header("Set-Cookie", type(self).set_cookie)
            self.end_headers()
            return
        body, ctype, encoding = type(self).files.get(
            self.path, (b"<html><body>ok</body></html>", "text/html", None))
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server(tmp_path, monkeypatch):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    _Handler.seen = []
    _Handler.redirect_to = None
    _Handler.set_cookie = None
    _Handler.files = {}
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(json.dumps({"version": 1, "values": [
        {"label": "personal_email", "kind": "email", "value": EMAIL, "class": "exact"}]}),
        encoding="utf-8")
    (tmp_path / "config.json").write_text(json.dumps({
        "local_endpoints": [{"scheme": "http", "host": "127.0.0.1", "port": port,
                             "service": "test", "allowed_ops": ["fetch"]}],
        "cookie_origins": [f"http://127.0.0.1:{port}"]}), encoding="utf-8")
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _cookie(domain, name, path="/", secure=False, host_only=False):
    return Cookie(0, name, "v", None, False, domain, not host_only, domain.startswith("."),
                  path, True, secure, int(time.time()) + 3600, False, None, None, {})


def test_fetch_ok_through_listed_local_endpoint(server):
    resp = fetcher.fetch(server + "/page")
    assert resp.status_code == 200
    assert _Handler.seen == [("/page", None)]


def test_redirect_to_protected_value_is_never_sent(server):
    _Handler.redirect_to = f"{server}/leak?email={EMAIL}"
    with pytest.raises(ep.EgressDenied) as err:
        fetcher.fetch(server + "/hop")
    assert err.value.decision.reason_code == "protected_value"
    assert [p for p, _ in _Handler.seen] == ["/hop"]


def test_redirect_to_unlisted_private_host_denied(server):
    _Handler.redirect_to = "http://10.9.9.9/internal"
    with pytest.raises(ep.EgressDenied) as err:
        fetcher.fetch(server + "/hop")
    assert err.value.decision.reason_code == "private_destination"


def test_denied_first_hop_opens_no_connection(server, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network touched")
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", boom)
    monkeypatch.setattr(ep.socket, "getaddrinfo", boom)
    with pytest.raises(ep.EgressDenied):
        fetcher.fetch(f"https://api.example/v2?email={EMAIL}")
    assert _Handler.seen == []


def test_cookie_suffix_trap_gets_nothing(server, monkeypatch):
    jar = CookieJar()
    jar.set_cookie(_cookie(".github.com", "gh_session"))
    monkeypatch.setattr(ep, "cookie_origin_allowed", lambda url: True)
    assert fetcher._cookie_header(jar, "https://evilgithub.com/") is None
    assert fetcher._cookie_header(jar, "https://github.com/").startswith("gh_session=")
    assert fetcher._cookie_header(jar, "https://api.github.com/") is not None


def test_cookie_scope_host_only_path_secure(server, monkeypatch):
    jar = CookieJar()
    jar.set_cookie(_cookie("docs.example", "host_only", host_only=True))
    jar.set_cookie(_cookie(".example", "pathed", path="/private"))
    jar.set_cookie(_cookie(".example", "secure_only", secure=True))
    monkeypatch.setattr(ep, "cookie_origin_allowed", lambda url: True)
    sub = fetcher._cookie_header(jar, "http://sub.docs.example/public") or ""
    assert "host_only" not in sub and "pathed" not in sub and "secure_only" not in sub
    assert "pathed" in (fetcher._cookie_header(jar, "http://a.example/private/x") or "")
    assert "secure_only" in (fetcher._cookie_header(jar, "https://a.example/") or "")


def test_cookies_not_loaded_for_unlisted_origin(server, monkeypatch):
    monkeypatch.setattr(fetcher, "_load_cookies", lambda b: pytest.fail("cookie store read"))
    (ep.policy_dir() / "config.json").write_text(json.dumps({
        "local_endpoints": json.loads((ep.policy_dir() / "config.json")
                                      .read_text())["local_endpoints"],
        "cookie_origins": []}), encoding="utf-8")
    ep._cached = None
    fetcher.fetch(server + "/page", browser="edge", session_kind="attended")


def test_cross_origin_redirect_drops_cookies(server, monkeypatch):
    jar = CookieJar()
    jar.set_cookie(_cookie("127.0.0.1", "sid", host_only=True))
    monkeypatch.setattr(fetcher, "_load_cookies", lambda b: jar)
    # Same server reached by a second listed origin name: cookies must not follow.
    port = server.rsplit(":", 1)[1]
    cfg = json.loads((ep.policy_dir() / "config.json").read_text())
    cfg["local_endpoints"].append({"scheme": "http", "host": "localhost", "port": int(port),
                                   "service": "test", "allowed_ops": ["fetch"]})
    (ep.policy_dir() / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    ep._cached = None
    real = fetcher.socket.getaddrinfo
    monkeypatch.setattr(fetcher.socket, "getaddrinfo",
                        lambda h, *a, **k: real("127.0.0.1" if h == "localhost" else h, *a, **k))
    _Handler.redirect_to = f"http://localhost:{port}/landing"
    fetcher.fetch(server + "/hop", browser="edge", session_kind="attended")
    assert _Handler.seen[0] == ("/hop", "sid=v")
    assert _Handler.seen[1] == ("/landing", None)


def test_pinned_backend_refuses_unchecked_host():
    backend = fetcher._PinnedBackend()
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("unchecked.example", 443)


def test_default_browser_is_anonymous():
    import inspect
    assert inspect.signature(fetcher.fetch).parameters["browser"].default == "none"


# --- download_to_staging -------------------------------------------------------

def test_download_pdf_lands_under_server_chosen_name(server, tmp_path):
    from siftfetch.downloader import download_to_staging
    _Handler.files = {"/../../evil.pdf": (b"%PDF-1.7 body", "application/pdf", None),
                      "/paper.pdf": (b"%PDF-1.7 body", "application/pdf", None)}
    out = download_to_staging(server + "/paper.pdf", tmp_path / "stage", "pdf")
    path = Path(out["path"])
    assert path.parent == tmp_path / "stage" / "downloads"
    assert path.name == out["sha256"][:16] + ".pdf" and path.read_bytes() == b"%PDF-1.7 body"


def test_download_type_mismatch_is_deleted(server, tmp_path):
    from siftfetch.downloader import DownloadRejected, download_to_staging
    _Handler.files = {"/fake.pdf": (b"<html>login</html>", "text/html", None)}
    with pytest.raises(DownloadRejected) as err:
        download_to_staging(server + "/fake.pdf", tmp_path / "stage", "pdf")
    assert err.value.reason == "type_mismatch"
    assert list((tmp_path / "stage" / "downloads").iterdir()) == []


def test_download_size_cap_counts_decoded_bytes(server, tmp_path):
    import gzip
    from siftfetch.downloader import DownloadRejected, download_to_staging
    bomb = gzip.compress(b"a" * 2_000_000)
    _Handler.files = {"/bomb.txt": (bomb, "text/plain", "gzip")}
    with pytest.raises(DownloadRejected) as err:
        download_to_staging(server + "/bomb.txt", tmp_path / "stage", "text", max_bytes=100_000)
    assert err.value.reason == "too_large"
    assert list((tmp_path / "stage" / "downloads").iterdir()) == []


def test_download_cannot_raise_hard_limit():
    from siftfetch import downloader
    assert downloader.HARD_MAX_BYTES == 50_000_000


def test_download_redirect_to_protected_value_denied(server, tmp_path):
    from siftfetch.downloader import download_to_staging
    _Handler.redirect_to = f"{server}/x.pdf?email={EMAIL}"
    with pytest.raises(ep.EgressDenied):
        download_to_staging(server + "/hop", tmp_path / "stage", "pdf")
    assert [p for p, _ in _Handler.seen] == ["/hop"]


def test_download_validates_json_and_xml(server, tmp_path):
    from siftfetch.downloader import DownloadRejected, download_to_staging
    _Handler.files = {"/a.json": (b'{"ok": 1}', "application/json", None),
                      "/b.json": (b"{nope", "application/json", None),
                      "/c.xml": (b"<r><x/></r>", "application/xml", None)}
    download_to_staging(server + "/a.json", tmp_path / "s", "json")
    download_to_staging(server + "/c.xml", tmp_path / "s", "xml")
    with pytest.raises(DownloadRejected):
        download_to_staging(server + "/b.json", tmp_path / "s", "json")


def test_download_refuses_linked_staging_dir(server, tmp_path):
    import os
    from siftfetch.downloader import DownloadRejected, download_to_staging
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "stage"
    try:
        os.symlink(real, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation not permitted on this machine")
    with pytest.raises(DownloadRejected) as err:
        download_to_staging(server + "/page", link, "html")
    assert err.value.reason == "unsafe_staging"


@pytest.mark.parametrize("status, body, walled", [
    (403, "", True),
    (429, "slow down", True),
    (503, "<html>maintenance</html>", True),
    (202, "", True),
    (200, "<title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/x'>", True),
    (200, "<html><body>ordinary page</body></html>", False),
    (404, "not found", False),
])
def test_bot_wall(status, body, walled):
    assert fetcher.bot_wall(status, body) is walled


def test_long_article_naming_a_wall_vendor_is_not_a_wall():
    assert not fetcher.bot_wall(200, "<p>" + "An essay about captcha and DataDome. " * 2000)


def test_response_cookie_never_replayed_on_next_hop(server):
    # httpx's client jar would send a hop's Set-Cookie on the next hop.
    _Handler.set_cookie = "trap=1; Path=/"
    _Handler.redirect_to = f"{server}/landing"
    fetcher.fetch(server + "/hop")
    assert _Handler.seen == [("/hop", None), ("/landing", None)]


def test_owner_cookie_not_sent_after_bouncing_back(server, monkeypatch):
    jar = CookieJar()
    jar.set_cookie(_cookie("127.0.0.1", "sid", host_only=True))
    monkeypatch.setattr(fetcher, "_load_cookies", lambda b: jar)
    port = server.rsplit(":", 1)[1]
    cfg = json.loads((ep.policy_dir() / "config.json").read_text())
    cfg["local_endpoints"].append({"scheme": "http", "host": "localhost", "port": int(port),
                                   "service": "test", "allowed_ops": ["fetch"]})
    (ep.policy_dir() / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    ep._cached = None
    real = fetcher.socket.getaddrinfo
    monkeypatch.setattr(fetcher.socket, "getaddrinfo",
                        lambda h, *a, **k: real("127.0.0.1" if h == "localhost" else h, *a, **k))
    # 127.0.0.1/hop -> localhost/hop2 -> 127.0.0.1/back: only the first hop gets the cookie.
    _Handler.redirect_to = f"http://localhost:{port}/hop2"
    orig = _Handler.do_GET

    def bounce(self):
        if self.path == "/hop2":
            type(self).seen.append((self.path, self.headers.get("Cookie")))
            self.send_response(302)
            self.send_header("Location", f"{server}/back")
            self.end_headers()
            return
        orig(self)
    monkeypatch.setattr(_Handler, "do_GET", bounce)
    fetcher.fetch(server + "/hop", browser="edge", session_kind="attended")
    assert _Handler.seen == [("/hop", "sid=v"), ("/hop2", None), ("/back", None)]


@pytest.mark.parametrize("path, ok", [
    ("https://docs.example/", True),
    ("{server}/listed", True),            # the fixture's listed local endpoint
    ("http://127.0.0.1:9/", False),       # loopback, but not listed
    ("http://localhost/", False),
    ("http://docs.example/", False),
    ("http://10.0.0.5/", False),
])
def test_cookie_scheme_https_or_listed_endpoint(server, path, ok):
    assert fetcher._cookie_scheme_ok(path.format(server=server)) is ok


def _owner_cookie(monkeypatch, attended_only=None):
    jar = CookieJar()
    jar.set_cookie(_cookie("127.0.0.1", "sid", host_only=True))
    monkeypatch.setattr(fetcher, "_load_cookies", lambda b: jar)
    if attended_only is not None:
        path = ep.policy_dir() / "config.json"
        cfg = json.loads(path.read_text())
        cfg["cookies_attended_only"] = attended_only
        path.write_text(json.dumps(cfg), encoding="utf-8")
        ep._cached = None


@pytest.mark.parametrize("kind, attended_only, sent", [
    ("attended", None, "sid=v"),        # default on: attended gets logins
    ("unattended", None, None),         # default on: headless gets nothing
    ("unknown", None, None),            # unknown counts as unattended
    ("unattended", False, "sid=v"),     # owner turned it off
    ("attended", True, "sid=v"),
])
def test_attended_only_logins(server, monkeypatch, kind, attended_only, sent):
    _owner_cookie(monkeypatch, attended_only)
    fetcher.fetch(server + "/page", browser="edge", session_kind=kind)
    assert _Handler.seen == [("/page", sent)]


def test_unattended_never_reads_cookie_store(server, monkeypatch):
    monkeypatch.setattr(fetcher, "_load_cookies", lambda b: pytest.fail("cookie store read"))
    fetcher.fetch(server + "/page", browser="edge")


def test_body_over_size_budget_stops(server, monkeypatch):
    monkeypatch.setattr(fetcher, "_MAX_BODY_BYTES", 50_000)
    _Handler.files["/big"] = (b"x" * 200_000, "text/html", None)
    with pytest.raises(fetcher.FetchBudgetExceeded, match="passed"):
        fetcher.fetch(server + "/big")


def test_gzip_body_is_capped_after_decoding(server, monkeypatch):
    import gzip
    monkeypatch.setattr(fetcher, "_MAX_BODY_BYTES", 50_000)
    _Handler.files["/bomb"] = (gzip.compress(b"x" * 500_000), "text/html", "gzip")
    with pytest.raises(fetcher.FetchBudgetExceeded):
        fetcher.fetch(server + "/bomb")


def _encoded(coding, data):
    import gzip
    import zlib
    if coding == "gzip":
        return gzip.compress(data)
    if coding == "deflate":
        return zlib.compress(data)
    if coding == "raw-deflate":
        c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        return c.compress(data) + c.flush()
    import brotli
    return brotli.compress(data)


@pytest.mark.parametrize("coding", ["gzip", "deflate", "raw-deflate", "br"])
def test_each_content_encoding_decodes_whole(server, coding):
    if coding == "br" and fetcher._brotli is None:
        pytest.skip("no patched brotli (>= 1.2.1) installed")
    page = b"<html><body>" + b"<p>line</p>" * 30_000 + b"</body></html>"
    header = "deflate" if coding == "raw-deflate" else coding
    _Handler.files["/enc"] = (_encoded(coding, page), "text/html", header)
    assert fetcher.fetch(server + "/enc").content == page


@pytest.mark.parametrize("coding", ["gzip", "br"])
def test_compression_bomb_never_expands_past_a_step(server, monkeypatch, coding):
    # httpx would decode a whole network chunk before the cap saw it, and
    # 16 KB of compressed zeros expands to megabytes in one go.
    import tracemalloc
    if coding == "br" and fetcher._brotli is None:
        pytest.skip("no patched brotli (>= 1.2.1) installed")
    monkeypatch.setattr(fetcher, "_MAX_BODY_BYTES", 1_000_000)
    _Handler.files["/bomb2"] = (_encoded(coding, bytes(60_000_000)), "text/html", coding)
    tracemalloc.start()
    try:
        with pytest.raises(fetcher.FetchBudgetExceeded):
            fetcher.fetch(server + "/bomb2")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 6_000_000, peak


def test_download_bomb_never_expands_past_a_step(server, tmp_path):
    import tracemalloc
    from siftfetch.downloader import DownloadRejected, download_to_staging
    _Handler.files["/bomb3"] = (_encoded("gzip", bytes(60_000_000)), "text/plain", "gzip")
    tracemalloc.start()
    try:
        with pytest.raises(DownloadRejected, match="too_large"):
            download_to_staging(server + "/bomb3", tmp_path / "stage", "text",
                                max_bytes=1_000_000)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 6_000_000, peak


def test_download_stops_at_deadline_even_when_headers_dribble(server, tmp_path, monkeypatch):
    from siftfetch import downloader
    from siftfetch.downloader import DownloadRejected, download_to_staging
    monkeypatch.setattr(downloader, "HARD_MAX_SECONDS", 0.5)
    for path in ("/slow-headers", "/drip"):
        start = time.monotonic()
        with pytest.raises(DownloadRejected, match="timeout"):
            download_to_staging(server + path, tmp_path / "stage", "text")
        assert time.monotonic() - start < 5, path


def test_concatenated_gzip_members_all_decode_and_end(server, monkeypatch):
    # A first member longer than one step must not loop on empty chunks.
    import gzip
    monkeypatch.setattr(fetcher, "_TOTAL_SECONDS", 10.0)
    first = b"a" * (fetcher._DECODE_STEP + 1)
    body = gzip.compress(first) + gzip.compress(b"b" * 10) + bytes(2) + b"trailing junk"
    _Handler.files["/multi"] = (body, "text/html", "gzip")
    assert fetcher.fetch(server + "/multi").content == first + b"b" * 10


def test_raw_deflate_that_looks_like_zlib_still_decodes(server):
    import zlib
    raw = bytes.fromhex("780100feff41010000ffff")  # a raw stored block
    expected = zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw)
    _Handler.files["/rawdef"] = (raw, "text/html", "deflate")
    assert fetcher.fetch(server + "/rawdef").content == expected


def test_corrupt_gzip_is_a_decoding_error(server):
    _Handler.files["/bad"] = (bytes.fromhex("1f8b0800") + b"garbage-not-deflate", "text/html", "gzip")
    with pytest.raises(httpx.DecodingError):
        fetcher.fetch(server + "/bad")


@pytest.mark.parametrize("version, ok", [
    ("1.2.0", False), ("1.0.9", False), ("1.2.1", True), ("1.3.0", True), ("bogus", False)])
def test_vulnerable_brotli_is_never_used(version, ok):
    from types import SimpleNamespace
    assert fetcher._brotli_patched(SimpleNamespace(__version__=version)) is ok


def test_br_body_is_refused_without_a_patched_brotli(server, monkeypatch):
    pytest.importorskip("brotli")
    monkeypatch.setattr(fetcher, "_brotli", None)
    _Handler.files["/br"] = (_encoded("br", b"<p>x</p>"), "text/html", "br")
    with pytest.raises(httpx.DecodingError):
        fetcher.fetch(server + "/br")


@pytest.mark.parametrize("header", ["gzip, br", "zstd", "compress"])
def test_unknown_or_stacked_encodings_are_refused(server, header):
    _Handler.files["/odd"] = (b"whatever", "text/html", header)
    with pytest.raises(httpx.DecodingError):
        fetcher.fetch(server + "/odd")


def test_endless_slow_body_stops_at_deadline(server, monkeypatch):
    monkeypatch.setattr(fetcher, "_TOTAL_SECONDS", 0.5)
    start = time.monotonic()
    with pytest.raises(fetcher.FetchBudgetExceeded, match="in total"):
        fetcher.fetch(server + "/drip")
    assert time.monotonic() - start < 5


def test_body_under_budget_reads_normally(server, monkeypatch):
    # Control: a page under the cap comes back whole, text and bytes both.
    monkeypatch.setattr(fetcher, "_MAX_BODY_BYTES", 50_000)
    _Handler.files["/fits"] = (b"y" * 40_000, "text/html", None)
    resp = fetcher.fetch(server + "/fits")
    assert resp.content == b"y" * 40_000 and resp.text == "y" * 40_000


def test_generated_headers_are_checked(server, monkeypatch):
    # An alias set to a protected value must not leave in the User-Agent.
    monkeypatch.setattr(ep, "contact_alias", lambda: EMAIL)
    with pytest.raises(ep.EgressDenied) as err:
        fetcher.fetch(server + "/page")
    assert err.value.decision.reason_code == "protected_value"
    assert _Handler.seen == []


def test_approved_alias_in_user_agent_passes(server, monkeypatch):
    # Control: the real alias, not a protected value, goes out as before.
    monkeypatch.setattr(ep, "contact_alias", lambda: "agent-contact@relay.example")
    fetcher.fetch(server + "/page")
    assert _Handler.seen == [("/page", None)]


def test_dribbled_headers_stop_at_deadline(server, monkeypatch):
    # The deadline covers the header phase too.
    monkeypatch.setattr(fetcher, "_TOTAL_SECONDS", 0.5)
    start = time.monotonic()
    with pytest.raises(fetcher.FetchBudgetExceeded):
        fetcher.fetch(server + "/slow-headers")
    assert time.monotonic() - start < 5


def test_error_status_body_is_readable(server):
    # Bot-wall recovery reads the body of a 403.
    with pytest.raises(httpx.HTTPStatusError) as err:
        fetcher.fetch(server + "/wall")
    assert err.value.response.status_code == 403
    assert fetcher.bot_wall(403, err.value.response.text)
