"""Real-browser page reads for sites that block automated fetches.

Some sites answer any non-browser client with a bot challenge. This opens a
real installed browser (Edge or Chrome, through Playwright), loads the page,
waits out the challenge and returns the HTML. It reads pages only: it never
clicks, types or submits, so text on a page cannot drive it anywhere.

- **Off by default.** The owner turns it on with ``browser_fetch`` in the
  egress config (``egress_policy.browser_fetch_settings``).
- **No logins.** Every read uses a fresh, empty browser profile, so no
  cookie or session of the owner's is present.
- **Every connection goes through a local egress proxy** (``egress_proxy``),
  the browser's only route out. It checks each host, resolves it itself
  (private, loopback and link-local refused) and connects only to the
  checked address. That covers redirect hops, workers, frames and anything
  else that opens a connection.
- **Read-only browsing.** In the browser, every request's URL and headers
  are value-checked, and only GET and HEAD pass: a page read never needs to
  send data. WebSockets are never connected.
- **Doesn't take over the desktop.** Playwright drives the browser over its
  debugging protocol, never the OS mouse or keyboard. The window is
  off-screen, minimized or visible, per the ``window`` setting; an agent can
  ask for a visible window on one read when the owner wants to watch.
- **Rate-limited** to ``max_per_minute`` page reads.

Headless browsers are refused by the same walls: in the author's tests,
headless Edge got through none of 9 walled sites, and a real Edge window got
through 5 of 6.
"""

from __future__ import annotations

import collections
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from siftfetch import egress_policy, egress_proxy, hidden_text
from siftfetch.egress_policy import EgressDenied

_CHALLENGE_TITLES = ("just a moment", "attention required", "please wait", "checking your browser")
_CHALLENGE_WAIT_S = 20.0
_SETTLE_MS = 6_000
_NAV_TIMEOUT_MS = 45_000
_MAX_HTML_CHARS = 15_000_000  # checked in the page before content() copies it out
# Not needed to read text, and skipping them keeps a page read fast and light.
_SKIPPED_RESOURCES = frozenset({"image", "media", "font"})
# OPTIONS is left out: it can carry a body, and a read never needs one.
_READ_METHODS = frozenset({"GET", "HEAD"})
# Network paths that neither route() nor the proxy see: WebRTC (UDP, STUN to
# any address) and speculative DNS/preconnect. Closed at launch.
_CLOSED_SIDE_CHANNELS = [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-features=NetworkPrediction,DnsOverHttps",
    "--dns-prefetch-disable",
]

_reads: collections.deque[float] = collections.deque()
_reads_lock = threading.Lock()


class BrowserFetchUnavailable(RuntimeError):
    """Browser reads are off, rate-limited, or the browser could not start."""


@dataclass(frozen=True)
class BrowserPage:
    url: str
    html: str
    title: str
    challenged: bool  # still on a challenge page when the wait ran out


def wanted(url: str, walled: bool) -> bool:
    """Whether the owner's settings call for a browser read of this URL."""
    settings = egress_policy.browser_fetch_settings()
    if settings["mode"] == "on-wall":
        return walled
    if settings["mode"] == "always-for-listed":
        host = (urlsplit(url).hostname or "").lower()
        listed = any(host == s or host.endswith("." + s) for s in settings["sites"])
        return listed or walled
    return False


def _take_rate_slot(per_minute: int) -> None:
    now = time.monotonic()
    with _reads_lock:
        while _reads and now - _reads[0] > 60:
            _reads.popleft()
        if len(_reads) >= per_minute:
            raise BrowserFetchUnavailable(
                f"browser reads are limited to {per_minute} a minute; try again shortly"
            )
        _reads.append(now)


def _window_args(window: str) -> list[str]:
    if window == "offscreen":
        return ["--window-position=-32000,-32000", "--window-size=1280,900"]
    if window == "minimized":
        return ["--start-minimized"]
    return ["--window-size=1280,900"]


def read_page(url: str, window: str | None = None) -> BrowserPage:
    """Load ``url`` in a real browser and return its HTML once past any challenge.

    ``window`` overrides the owner's default for this read: an agent passes
    ``"visible"`` when the owner wants to watch. On Windows 11, in every
    mode, keyboard focus stays in the window the
    owner was using, because Windows does not let a background process take
    the foreground.

    Raises:
        EgressDenied: the policy denied the page itself.
        BrowserFetchUnavailable: reads are off or rate-limited, Playwright is
            missing, or the browser failed to start or load the page.
    """
    settings = egress_policy.browser_fetch_settings()
    if settings["mode"] == "off":
        raise BrowserFetchUnavailable("browser reads are off (browser_fetch.mode)")
    decision = egress_policy.check_url(url, op="fetch", tool="browser-fetch")
    if decision.action != "allow":
        raise EgressDenied(decision)
    _take_rate_slot(settings["max_per_minute"])

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BrowserFetchUnavailable("playwright is not installed") from exc

    def gate(route) -> None:
        request = route.request
        if request.resource_type in _SKIPPED_RESOURCES:
            route.abort("blockedbyclient")
            return
        if request.url.startswith(("data:", "blob:")):
            route.continue_()
            return
        if request.method.upper() not in _READ_METHODS:
            route.abort("blockedbyclient")
            return
        headers = [(f"header:{k}", v) for k, v in request.headers.items()]
        body = request.post_data
        if body:
            headers.append(("body", body))
        checked = egress_policy.check_url(request.url, op="fetch", tool="browser-fetch",
                                          extra=headers)
        if checked.action == "allow":
            route.continue_()
        else:
            route.abort("blockedbyclient")

    def gate_socket(ws) -> None:
        # Never connect_to_server(): the socket then never reaches the network,
        # and its messages have nowhere to go. (Calling ws.close() here
        # deadlocks the sync API.)
        return

    try:
        with egress_proxy.EgressProxy() as proxy, sync_playwright() as pw:
            browser = pw.chromium.launch(
                channel=settings["browser"],
                headless=False,
                args=_window_args(window if window in egress_policy.BROWSER_WINDOWS
                                  else settings["window"])
                + _CLOSED_SIDE_CHANNELS + proxy.launch_args,
            )
            try:
                # Fresh profile: no logins. Service workers are blocked because
                # their requests bypass route().
                context = browser.new_context(service_workers="block")
                context.route("**/*", gate)
                context.route_web_socket(re.compile(".*"), gate_socket)
                page = context.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS)
                deadline = time.monotonic() + _CHALLENGE_WAIT_S
                while (page.title().lower().startswith(_CHALLENGE_TITLES)
                       and time.monotonic() < deadline):
                    page.wait_for_timeout(1_000)
                try:
                    page.wait_for_load_state("networkidle", timeout=_SETTLE_MS)
                except PlaywrightError:
                    pass  # busy pages never go idle; what has rendered is enough
                too_big = BrowserFetchUnavailable(
                    f"the page passed {_MAX_HTML_CHARS // 1_000_000} MB of HTML; not read")
                # Measured in the page first, before anything copies it out.
                if page.evaluate("document.documentElement.outerHTML.length") > _MAX_HTML_CHARS:
                    raise too_big
                try:
                    # Tag text the reader can't see, using the browser's final
                    # computed styles; hidden_text reads the tags.
                    page.evaluate(hidden_text.BROWSER_SCRIPT, hidden_text.BROWSER_ATTR)
                except PlaywrightError:
                    pass  # static detection still runs on the HTML
                title = page.title()
                html = page.content()
                # Again in bytes: the page's scripts can grow it in between.
                if len(html.encode("utf-8")) > _MAX_HTML_CHARS:
                    raise too_big
                return BrowserPage(
                    url=page.url,
                    html=html,
                    title=title,
                    challenged=title.lower().startswith(_CHALLENGE_TITLES),
                )
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise BrowserFetchUnavailable(f"browser read failed: {exc}") from exc
