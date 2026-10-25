"""Local egress proxy for real-browser reads.

The browser is launched with this proxy as its only route out, so every
connection it opens comes here first: the page, each redirect hop,
subresources, frames, workers and anything else that opens a socket. With an
HTTP proxy, Chromium leaves name resolution to the proxy, so the browser
never resolves a hostname itself (Chromium ``net/docs/proxy.md``).

For each connection the proxy runs the same per-hop check as the fetcher
(``fetcher._checked_address``): the policy check on the URL, then
resolution that refuses private, loopback and link-local addresses unless
the owner listed the endpoint. It connects only to the address that check
returned, so a hostname can't be re-resolved to somewhere else (DNS
rebinding).

- **https (CONNECT):** the proxy sees host and port only. Paths and bodies
  are checked by the browser-side route gate in ``browser_fetch``.
- **Plain http:** the proxy sees the full URL and checks it. Each request
  gets its own upstream connection, closed after the response, so a reused
  client connection can't carry a second request to the first host.

One proxy per read, on 127.0.0.1 with a random port, stopped after the read.
"""

from __future__ import annotations

import selectors
import socket
import socketserver
import threading
from urllib.parse import urlsplit

from siftfetch import fetcher

_MAX_HEAD = 64 * 1024
_IDLE_S = 30.0  # a tunnel with no traffic either way for this long is closed
_DROPPED_HEADERS = {b"proxy-connection", b"connection", b"keep-alive", b"proxy-authorization"}


class _Refused(Exception):
    pass


def _read_head(sock: socket.socket) -> tuple[bytes, bytes] | None:
    """Read up to the blank line; return (head, bytes already read past it)."""
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > _MAX_HEAD:
            return None
        chunk = sock.recv(8192)
        if not chunk:
            return None
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


def _split_host_port(target: str, default: int) -> tuple[str, int]:
    parts = urlsplit("//" + target)
    if not parts.hostname:
        raise _Refused("no host")
    return parts.hostname, parts.port or default


def _pipe(a: socket.socket, b: socket.socket, both_ways: bool) -> None:
    sel = selectors.DefaultSelector()
    sel.register(b, selectors.EVENT_READ, a)
    if both_ways:
        sel.register(a, selectors.EVENT_READ, b)
    try:
        while True:
            ready = sel.select(timeout=_IDLE_S)
            if not ready:
                return
            for key, _ in ready:
                data = key.fileobj.recv(65536)
                if not data:
                    return
                key.data.sendall(data)
    except OSError:
        return
    finally:
        sel.close()


class _Handler(socketserver.BaseRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(_IDLE_S)
        upstream = None
        try:
            got = _read_head(client)
            if got is None:
                return
            head, rest = got
            line, *headers = head.split(b"\r\n")
            method, target, version = line.decode("latin-1").split(" ", 2)
            if method.upper() == "CONNECT":
                host, port = _split_host_port(target, 443)
                upstream = self._connect(f"https://{host}:{port}/", port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
                _pipe(client, upstream, both_ways=True)
                return
            parts = urlsplit(target)
            if parts.scheme.lower() != "http" or not parts.hostname:
                raise _Refused("only absolute http:// requests and CONNECT are proxied")
            upstream = self._connect(target, parts.port or 80)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            kept = [h for h in headers
                    if h.split(b":", 1)[0].strip().lower() not in _DROPPED_HEADERS]
            upstream.sendall(f"{method} {path} {version}\r\n".encode("latin-1")
                             + b"".join(h + b"\r\n" for h in kept)
                             + b"Connection: close\r\n\r\n" + rest)
            # Response only from here: the client connection is not read
            # again, so it can't send a second request down this one.
            _pipe(client, upstream, both_ways=False)
        except _Refused as exc:
            self.server.refused.append(str(exc))
            try:
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                               b"Connection: close\r\n\r\n")
            except OSError:
                pass
        except (OSError, ValueError):
            return
        finally:
            if upstream is not None:
                upstream.close()

    def _connect(self, url: str, port: int) -> socket.socket:
        try:
            address = fetcher._checked_address(url, tool="browser-fetch")
        except Exception as exc:  # a denial, or a name that won't resolve
            raise _Refused(f"{urlsplit(url).hostname}: {type(exc).__name__}") from exc
        self.server.connected.append(f"{urlsplit(url).hostname}:{port}")
        return socket.create_connection((address, port), timeout=_IDLE_S)


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        # Host names only, for tests and diagnostics; never URLs or values.
        self.refused: list[str] = []
        self.connected: list[str] = []


class EgressProxy:
    """``with EgressProxy() as proxy:`` then launch with ``proxy.launch_args``."""

    def __enter__(self) -> "EgressProxy":
        self._server = _Server()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def launch_args(self) -> list[str]:
        # "<-loopback>" removes Chromium's implicit direct route to loopback
        # and link-local addresses, so those go through the proxy too.
        return [f"--proxy-server=http://127.0.0.1:{self.port}",
                "--proxy-bypass-list=<-loopback>"]

    @property
    def refused(self) -> list[str]:
        return list(self._server.refused)

    @property
    def connected(self) -> list[str]:
        return list(self._server.connected)

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
