"""Tests for the browser egress proxy, over raw sockets. No browser, no public network."""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from siftfetch import egress_policy as ep
from siftfetch import egress_proxy, fetcher

EMAIL = "pat.example@mailhost.test"


class _Sink(BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_GET(self):  # noqa: N802
        type(self).seen.append(self.path)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A listed local endpoint and an unlisted one, both real servers."""
    listed, listed_port = _serve()
    unlisted, unlisted_port = _serve()
    _Sink.seen = []
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(json.dumps({"version": 1, "values": [
        {"label": "personal_email", "kind": "email", "value": EMAIL, "class": "exact"}]}),
        encoding="utf-8")
    (tmp_path / "config.json").write_text(json.dumps({
        "local_endpoints": [{"scheme": s, "host": "127.0.0.1", "port": listed_port,
                             "service": "test", "allowed_ops": ["fetch"]}
                            for s in ("http", "https")]}), encoding="utf-8")
    with egress_proxy.EgressProxy() as proxy:
        yield proxy, listed_port, unlisted_port
    listed.shutdown()
    unlisted.shutdown()


def _send(proxy_port: int, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as s:
        s.sendall(data)
        out = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out


def test_plain_http_to_listed_endpoint_is_forwarded(lab):
    proxy, listed, _ = lab
    out = _send(proxy.port, f"GET http://127.0.0.1:{listed}/page HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{listed}\r\n\r\n".encode())
    assert out.startswith(b"HTTP/1.0 200") or out.startswith(b"HTTP/1.1 200")
    assert _Sink.seen == ["/page"]


def test_plain_http_with_protected_value_is_refused(lab):
    proxy, listed, _ = lab
    out = _send(proxy.port, f"GET http://127.0.0.1:{listed}/x?email={EMAIL} HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{listed}\r\n\r\n".encode())
    assert out.startswith(b"HTTP/1.1 403")
    assert _Sink.seen == []


def test_unlisted_loopback_is_refused_both_ways(lab):
    proxy, _, unlisted = lab
    for request in (f"CONNECT 127.0.0.1:{unlisted} HTTP/1.1\r\n\r\n",
                    f"GET http://127.0.0.1:{unlisted}/ HTTP/1.1\r\nHost: x\r\n\r\n"):
        assert _send(proxy.port, request.encode()).startswith(b"HTTP/1.1 403")
    assert _Sink.seen == []


def test_hostname_resolving_to_loopback_is_refused(lab, monkeypatch):
    # DNS rebinding: a public-looking name that resolves to this machine.
    proxy, _, unlisted = lab
    real = socket.getaddrinfo

    def resolver(host, *a, **k):
        return real("127.0.0.1" if host == "rebind.example" else host, *a, **k)
    monkeypatch.setattr(ep.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", resolver)
    out = _send(proxy.port, f"CONNECT rebind.example:{unlisted} HTTP/1.1\r\n\r\n".encode())
    assert out.startswith(b"HTTP/1.1 403")
    assert _Sink.seen == []


def test_connect_tunnel_to_listed_endpoint_works(lab):
    # Control for the refusals above: an allowed CONNECT tunnels traffic.
    proxy, listed, _ = lab
    out = _send(proxy.port, f"CONNECT 127.0.0.1:{listed} HTTP/1.1\r\n\r\n"
                            f"GET /tunneled HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            f"Connection: close\r\n\r\n".encode())
    assert out.startswith(b"HTTP/1.1 200 Connection Established")
    assert _Sink.seen == ["/tunneled"]


def test_reused_client_connection_cannot_send_a_second_request(lab):
    # A second request on the same client connection would otherwise ride the
    # first host's upstream connection without a check.
    proxy, listed, _ = lab
    out = _send(proxy.port, f"GET http://127.0.0.1:{listed}/first HTTP/1.1\r\n"
                            f"Host: 127.0.0.1\r\n\r\n"
                            f"GET /second?email={EMAIL} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                            .encode())
    assert b"200" in out.split(b"\r\n", 1)[0]
    assert _Sink.seen == ["/first"]


def test_launch_args_route_loopback_through_proxy(lab):
    proxy, _, _ = lab
    assert f"--proxy-server=http://127.0.0.1:{proxy.port}" in proxy.launch_args
    assert "--proxy-bypass-list=<-loopback>" in proxy.launch_args
