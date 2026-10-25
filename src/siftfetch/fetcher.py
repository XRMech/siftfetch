"""HTTP fetcher with optional browser cookie support.

Every hop (the first request and each redirect) passes the egress policy
before any connection is made, and connects to the address that was checked,
so DNS cannot be swapped between the check and the connection. Fetches are
anonymous by default; browser cookies are attached only for origins the owner
lists in ``cookie_origins`` and are scoped by the stdlib cookie policy
(domain, host-only, path, secure). Cookies are loaded per request and never
persisted by this module.
"""

import contextlib
import queue
import re
import socket
import sys
import threading
import time
import urllib.request
import zlib
from collections.abc import Iterator
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from siftfetch import egress_policy
from siftfetch.egress_policy import EgressDenied

_COOKIE_TIMEOUT = 5.0  # seconds to wait for browser cookie store before giving up

_AGENT_NAME = "agent-web-fetch/1.0 (research agent"


def _user_agent() -> str:
    """An honest automated-client identity, with the owner's contact alias.

    A browser string on a non-browser connection is what bot walls look for:
    Wikipedia rejects it outright and accepts an identified client. A 30-site
    A/B on 2026-10-24 found no site that served the browser string and refused
    this one. The alias is the owner's approved stand-in, never a protected
    value.
    """
    alias = egress_policy.contact_alias()
    return f"{_AGENT_NAME}; contact: {alias})" if alias else f"{_AGENT_NAME})"

_TIMEOUT = 15.0  # seconds per operation (connect, read, write)

# Bot walls: anti-bot services answer an automated client with a block status
# or a small challenge page instead of the content. Markers are checked only on
# short bodies so an article that mentions "captcha" is not mistaken for one.
_WALL_STATUSES = frozenset({403, 429, 503})
_WALL_MARKERS = re.compile(
    r"cf-chl|challenge-platform|Just a moment\.\.\.|Attention Required! \| Cloudflare|"
    r"_Incapsula_Resource|Pardon Our Interruption|perimeterx|px-captcha|"
    r"DataDome|captcha-delivery\.com",
    re.IGNORECASE,
)
_WALL_BODY_MAX = 30_000


def bot_wall(status: int, body: str) -> bool:
    """True when a response looks like an anti-bot block, not the page."""
    if status in _WALL_STATUSES:
        return True
    if status == 202 and len(body) < _WALL_BODY_MAX:
        return True  # an empty "accepted, run this script" holding page
    return len(body) < _WALL_BODY_MAX and bool(_WALL_MARKERS.search(body))

_MAX_REDIRECTS = 5
# Budgets checked while the body streams, before anything parses it.
_MAX_BODY_BYTES = 10_000_000  # decoded
_TOTAL_SECONDS = 60.0  # all hops and the body together


class FetchBudgetExceeded(Exception):
    """The response passed the size or time budget; reading stopped there."""


def _load_cookies(browser: str) -> CookieJar | None:
    """Load cookies from the specified browser's cookie store.

    Returns None if loading fails (browser closed, unsupported, etc.).
    """
    if browser == "none":
        return None

    try:
        import browser_cookie3 as bc3
    except ImportError:
        print("Warning: browser_cookie3 not installed, skipping cookies", file=sys.stderr)
        return None

    loaders = {
        "chrome": bc3.chrome,
        "edge": bc3.edge,
    }
    loader = loaders.get(browser)
    if not loader:
        print(f"Warning: unsupported browser '{browser}', skipping cookies", file=sys.stderr)
        return None

    # Run cookie loading in a daemon thread so we can abandon it if it hangs.
    # ThreadPoolExecutor is intentionally avoided: its __exit__ calls
    # shutdown(wait=True), which blocks until the thread finishes even after
    # a timeout — defeating the purpose of the timeout entirely.
    result_q: queue.Queue = queue.Queue()

    def _load() -> None:
        try:
            result_q.put(loader())
        except Exception as exc:
            result_q.put(exc)

    t = threading.Thread(target=_load, daemon=True)
    t.start()

    try:
        outcome = result_q.get(timeout=_COOKIE_TIMEOUT)
    except queue.Empty:
        print(
            f"Warning: {browser} cookie load timed out after {_COOKIE_TIMEOUT}s "
            "(browser may be holding a lock), falling back to unauthenticated fetch",
            file=sys.stderr,
        )
        return None

    if isinstance(outcome, Exception):
        print(
            f"Warning: could not load {browser} cookies ({outcome}), "
            "falling back to unauthenticated fetch",
            file=sys.stderr,
        )
        return None

    return outcome


def _cookie_header(jar: CookieJar | None, url: str) -> str | None:
    """Cookie header for this URL, or None when cookies are not allowed here.

    The stdlib policy applies domain-boundary, host-only, path, secure and
    expiry rules; a plain suffix test would hand ``github.com`` cookies to
    ``evilgithub.com``.
    """
    if jar is None or not egress_policy.cookie_origin_allowed(url):
        return None
    # The default policy sends cookies set without a Domain attribute to
    # subdomains too; browsers treat those as host-only, and so does this.
    jar.set_policy(DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain))
    request = urllib.request.Request(url)
    jar.add_cookie_header(request)
    return request.get_header("Cookie")


def _cookie_scheme_ok(url: str) -> bool:
    """Owner cookies travel over https only, or plain http to an owner-listed
    local endpoint (a service on this machine)."""
    if urlsplit(url).scheme.lower() == "https":
        return True
    return egress_policy.destination_allowed(url)


class _PinnedBackend(httpcore.SyncBackend):
    """Connects only to addresses the egress check resolved for a host."""

    def __init__(self) -> None:
        super().__init__()
        self.pins: dict[str, str] = {}

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        address = self.pins.get(host)
        if address is None:
            raise httpcore.ConnectError(f"{host} was not checked by the egress policy")
        return super().connect_tcp(address, port, timeout, local_address, socket_options)


class _PinnedTransport(httpx.HTTPTransport):
    """HTTP transport whose connections go through a _PinnedBackend.

    httpx does not expose httpcore's network_backend, so the pool is replaced
    after construction. TLS still verifies and sends SNI for the original
    host: httpcore takes server_hostname from the request origin, not from the
    address connected to. Environment proxies are ignored (trust_env=False)
    because a proxy would resolve the host itself and bypass the pin.
    """

    def __init__(self, backend: _PinnedBackend) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=backend,
        )


def _checked_address(url: str, tool: str = "siftfetch",
                     headers: dict[str, str] | None = None) -> str:
    """Run the egress policy on one hop and return the address to connect to.

    ``headers`` are the request's own headers, checked with the URL. The
    Cookie header is left out on purpose: it goes only to owner-listed
    origins, and login cookies routinely hold the owner's own details.
    """
    extra = [(f"header:{k}", v) for k, v in (headers or {}).items() if k.lower() != "cookie"]
    decision = egress_policy.check_url(url, op="fetch", tool=tool, extra=extra)
    if decision.action != "allow":
        raise EgressDenied(decision)
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if egress_policy.destination_allowed(url):
        addresses = [info[4][0] for info in
                     socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)]
    else:
        resolved = egress_policy.resolve_public(parts.hostname, port)
        if isinstance(resolved, egress_policy.Decision):
            raise EgressDenied(resolved)
        addresses = resolved
    if not addresses:
        raise httpx.ConnectError(f"could not resolve {parts.hostname}")
    return addresses[0]


def fetch(
    url: str,
    browser: str = "none",
    timeout: float = _TIMEOUT,
    session_kind: str = "unattended",
) -> httpx.Response:
    """Fetch a URL, checking the egress policy on every hop.

    Args:
        url: The URL to fetch.
        browser: "none" (default), "chrome" or "edge". Cookies from the
            browser are attached only for origins listed in cookie_origins.
        timeout: Read timeout in seconds.
        session_kind: "attended" or "unattended" (default). With the owner's
            ``cookies_attended_only`` on, unattended callers get no cookies.

    Returns:
        httpx.Response object for the final hop, body already read.

    Raises:
        EgressDenied: The policy denied a hop; nothing was sent for it.
        httpx.HTTPStatusError: On 4xx/5xx responses.
        httpx.TooManyRedirects: More than _MAX_REDIRECTS hops.
        FetchBudgetExceeded: The body passed 10 MB decoded, or the fetch
            passed 60 s in total.
    """
    deadline = time.monotonic() + _TOTAL_SECONDS
    try:
        with checked_response(url, browser=browser, timeout=timeout, stream=True,
                              session_kind=session_kind, deadline=deadline,
                              raise_status=False) as resp:
            # What Response.read() does, with the budgets checked per chunk.
            resp._content = _read_capped(resp, deadline)
    except (httpx.TransportError, httpx.StreamError) as exc:
        if time.monotonic() >= deadline:
            raise FetchBudgetExceeded(
                f"stopped reading {urlsplit(url).hostname}: the fetch passed "
                f"{_TOTAL_SECONDS:.0f} s in total.") from exc
        raise
    # After the body is read, so a caller handling a 403 or 503 (bot-wall
    # recovery) can still read the page that came with it.
    resp.raise_for_status()
    return resp


# Bodies are decoded here, not by httpx: httpx expands a whole network chunk
# before anything can count it, and a 16 KB chunk of brotli can expand to
# gigabytes. Each step below yields at most _DECODE_STEP bytes.
_RAW_CHUNK = 16_384
_DECODE_STEP = 262_144
try:
    import brotli as _brotli
except ImportError:
    _brotli = None


def _brotli_patched(module) -> bool:
    """brotli 1.0.3 to 1.2.0 has a decoder out-of-bounds write that a crafted
    body can trigger (CVE-2026-111497, GHSA-9v8h-qqgm-4m35); 1.2.1 fixes it
    and is also the first with ``output_buffer_limit``."""
    try:
        return tuple(int(p) for p in module.__version__.split(".")[:3]) >= (1, 2, 1)
    except (AttributeError, ValueError):
        return False


if _brotli is not None and not _brotli_patched(_brotli):
    _brotli = None  # br is then neither requested nor decoded
_ACCEPT_ENCODING = "gzip, deflate, br" if _brotli else "gzip, deflate"


def _zlib_steps(data_chunks: Iterator[bytes], wbits: int | None) -> Iterator[bytes]:
    """Decode gzip or deflate, never more than _DECODE_STEP bytes per yield.

    gzip may hold several members back to back (RFC 1952), each decoded in
    turn; anything else after the end of the stream is dropped.
    """
    gzip = wbits is not None and wbits > zlib.MAX_WBITS
    guessed_zlib = False
    produced = False
    d = None
    for data in data_chunks:
        buf = data
        while True:
            if d is None:
                if wbits is None:
                    # "deflate" is meant to be zlib-wrapped, but servers also
                    # send raw deflate, whose first bytes can look like a zlib
                    # header; a wrong guess is retried as raw below.
                    guessed_zlib = (len(buf) > 1 and buf[0] & 0x0F == 8
                                    and ((buf[0] << 8) | buf[1]) % 31 == 0)
                    wbits = zlib.MAX_WBITS if guessed_zlib else -zlib.MAX_WBITS
                d = zlib.decompressobj(wbits)
            try:
                out = d.decompress(buf, _DECODE_STEP)
            except zlib.error as exc:
                if guessed_zlib and not produced:
                    guessed_zlib, wbits, d = False, -zlib.MAX_WBITS, None
                    continue
                raise httpx.DecodingError(f"bad compressed body: {exc}") from exc
            if out:
                produced = True
                yield out
            if d.eof:
                rest, d = d.unused_data, None
                if gzip and rest[:2] == b"\x1f\x8b":
                    buf = rest
                    continue
                return
            # Either input is left, or output stopped at the step limit and
            # more may be pending; both make progress on the next call.
            if not d.unconsumed_tail and len(out) < _DECODE_STEP:
                break
            buf = d.unconsumed_tail
    if d is not None:
        yield d.flush()


def _brotli_steps(data_chunks: Iterator[bytes]) -> Iterator[bytes]:
    d = _brotli.Decompressor()
    try:
        for data in data_chunks:
            out = d.process(data, output_buffer_limit=_DECODE_STEP)
            yield out
            # A full buffer can leave output pending even when the decoder
            # says it can take more input, so drain until a call comes up short.
            while len(out) >= _DECODE_STEP or not d.can_accept_more_data():
                out = d.process(b"", output_buffer_limit=_DECODE_STEP)
                if not out:
                    break
                yield out
    except _brotli.error as exc:
        raise httpx.DecodingError(f"bad compressed body: {exc}") from exc


def _decoded(resp: httpx.Response) -> Iterator[bytes]:
    raw = resp.iter_raw(_RAW_CHUNK)
    codings = [c.strip().lower() for c in resp.headers.get("content-encoding", "").split(",")]
    codings = [c for c in codings if c and c != "identity"]
    if not codings:
        return raw
    if len(codings) > 1:
        raise httpx.DecodingError(f"unsupported content encoding: {', '.join(codings)}")
    if codings[0] in ("gzip", "x-gzip"):
        return _zlib_steps(raw, zlib.MAX_WBITS | 16)
    if codings[0] == "deflate":
        return _zlib_steps(raw, None)
    if codings[0] == "br" and _brotli:
        return _brotli_steps(raw)
    raise httpx.DecodingError(f"unsupported content encoding: {codings[0]}")


def _read_capped(resp: httpx.Response, deadline: float) -> bytes:
    chunks: list[bytes] = []
    size = 0
    host = urlsplit(str(resp.url)).hostname
    for chunk in _decoded(resp):
        size += len(chunk)
        if size > _MAX_BODY_BYTES:
            raise FetchBudgetExceeded(
                f"stopped reading {host}: the page passed {_MAX_BODY_BYTES // 1_000_000} MB. "
                "Look for a smaller source, such as a section page or an API.")
        if time.monotonic() > deadline:
            raise FetchBudgetExceeded(
                f"stopped reading {host}: the fetch passed {_TOTAL_SECONDS:.0f} s in total.")
        chunks.append(chunk)
    return b"".join(chunks)


@contextlib.contextmanager
def _watchdog(client: httpx.Client, deadline: float | None) -> Iterator[None]:
    """Close ``client`` at ``deadline``; closing its sockets ends a blocked read."""
    if deadline is None:
        yield
        return
    timer = threading.Timer(max(0.0, deadline - time.monotonic()), client.close)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


@contextlib.contextmanager
def checked_response(url: str, *, browser: str = "none", timeout: float = _TIMEOUT,
                     stream: bool, session_kind: str = "unattended",
                     deadline: float | None = None,
                     raise_status: bool = True) -> Iterator[httpx.Response]:
    """Yield the final response after policy-checking and following each hop.

    With stream=True the body is not read yet; the caller reads it inside the
    context and the connection closes on exit. At ``deadline`` (a monotonic
    time) a watchdog closes the client, so a server dribbling headers or a
    stalled hop can't run past it.
    """
    # The browser store is read only when the starting origin may carry
    # cookies; reading it is slow and exposes every session to this process.
    jar = (_load_cookies(browser)
           if browser != "none" and egress_policy.login_cookies_allowed(session_kind)
           and egress_policy.cookie_origin_allowed(url) else None)

    base_headers = {
        "User-Agent": _user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": _ACCEPT_ENCODING,
    }

    # Explicit per-operation limits so a slow server can't stall indefinitely;
    # each hop gets its own budget.
    httpx_timeout = httpx.Timeout(
        connect=5.0,
        read=timeout,
        write=5.0,
        pool=2.0,
    )
    backend = _PinnedBackend()
    current = url
    start_origin = egress_policy._origin_of(url)
    on_start_origin = True
    with httpx.Client(transport=_PinnedTransport(backend), follow_redirects=False,
                      timeout=httpx_timeout) as client, _watchdog(client, deadline):
        for _ in range(_MAX_REDIRECTS + 1):
            if deadline is not None and time.monotonic() >= deadline:
                raise httpx.ReadTimeout("total fetch deadline passed")
            host = urlsplit(current).hostname
            headers = dict(base_headers)
            # Generated headers (the User-Agent carries the contact alias) are
            # checked with the URL: a misconfigured alias never leaves.
            backend.pins[host] = _checked_address(current, headers=headers)
            # Owner cookies go only to the starting origin, and stop for good
            # once a redirect leaves it, so a bounce back carries nothing.
            on_start_origin = on_start_origin and egress_policy._origin_of(current) == start_origin
            cookie = _cookie_header(jar, current) if on_start_origin and _cookie_scheme_ok(current) else None
            if cookie:
                headers["Cookie"] = cookie
            # Response cookies never persist: httpx would otherwise replay a
            # Set-Cookie from one hop on the next.
            client.cookies.clear()
            resp = client.send(client.build_request("GET", current, headers=headers),
                               stream=stream)
            client.cookies.clear()
            if not (resp.is_redirect and "location" in resp.headers):
                try:
                    if raise_status:
                        resp.raise_for_status()
                    yield resp
                finally:
                    resp.close()
                return
            resp.close()
            current = urljoin(str(resp.url), resp.headers["location"])
    raise httpx.TooManyRedirects(f"more than {_MAX_REDIRECTS} redirects", request=resp.request)


def list_available_sessions() -> list[dict]:
    """List available browser cookie jars.

    Returns a list of dicts with browser name and status.
    """
    results = []
    try:
        import browser_cookie3 as bc3
    except ImportError:
        return [{"browser": "none", "status": "browser_cookie3 not installed"}]

    for name, loader in [("chrome", bc3.chrome), ("edge", bc3.edge)]:
        try:
            jar = loader()
            count = sum(1 for _ in jar)
            results.append({
                "browser": name,
                "status": "available",
                "cookie_count": count,
            })
        except Exception as exc:
            results.append({
                "browser": name,
                "status": f"unavailable: {exc}",
            })
    return results
