"""Web search via DDGS (no API key required)."""

import logging
from collections import Counter
from time import monotonic
from urllib.parse import urlsplit

from ddgs import DDGS
from ddgs.exceptions import DDGSException, RatelimitException, TimeoutException

from siftfetch import egress_policy
from siftfetch.domains import normalize_host
from siftfetch.egress_policy import EgressDenied
from siftfetch.injection_scan import safe_metadata


def search_web(query: str, max_results: int = 5) -> list[dict]:
    """Search the web via DDGS after the egress policy approves the query.

    DDGS is constructed without ``api_url``, which keeps its peer-to-peer
    result cache (``ddgs.dht``) off: with it on, queries would also be shared
    with other DDGS peers. Its "auto" backend may send the query to several
    search engines, not only DuckDuckGo.

    Args:
        query: Search query string.
        max_results: Maximum number of results to return (1-20).

    Returns:
        List of dicts with title, url, snippet and optional quality_flags.

    Raises:
        EgressDenied: The outbound policy denied a search attempt.
    """
    max_results = max(1, min(max_results, 20))
    for backend in ("auto", "yahoo"):
        decision = egress_policy.check_search(query)
        if decision.action != "allow":
            raise EgressDenied(decision)
        raw = _provider_results(query, max_results, backend)
        results = []
        discarded = Counter()
        for item in raw:
            reason = _discard_reason(item)
            if reason:
                discarded[reason] += 1
                continue
            results.append({
                "title": item.get("title", ""),
                "url": item["href"],
                "snippet": item.get("body", ""),
            })
            if len(results) == max_results:
                break
        for reason, count in discarded.items():
            logging.getLogger(__name__).info("Search rows discarded reason=%s count=%d", reason, count)
        if results:
            _flag_mixed_titles(results)
            return results
    return []


def _discard_reason(item: object) -> str | None:
    if not isinstance(item, dict) or not all(isinstance(item.get(k, ""), str) for k in ("title", "body")):
        return "malformed_row"
    url = item.get("href")
    if not isinstance(url, str) or not url or safe_metadata(url) != url:
        return "invalid_url"
    if any(c.isspace() or not c.isprintable() or c in '\\<>"' for c in url):
        return "invalid_url"
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None or parts.port == 0:
            return "invalid_url"
        host = normalize_host(parts.hostname)
    except ValueError:
        return "invalid_url"
    if (host == "bing.com" or host.endswith(".bing.com")) and parts.path.rstrip("/").lower() == "/aclick":
        return "ad_redirect"
    return None


def _flag_mixed_titles(results: list[dict]) -> None:
    titles = [" ".join(row["title"].casefold().split()) for row in results]
    for row, title in zip(results, titles):
        # Require two distinct, non-overlapping peer titles. Shared hotel
        # names, duplicate rows and nested shorter titles alone are ambiguous.
        matches = {
            peer for other, peer in zip(results, titles)
            if other["url"] != row["url"] and len(peer) >= 12 and peer != title and peer in title
        }
        if any(title.find(a) + len(a) <= title.rfind(b) for a in matches for b in matches if a != b):
            row["quality_flags"] = ["mixed_listing"]


def _provider_results(query: str, max_results: int, backend: str) -> list[dict]:
    started = monotonic()
    try:
        return DDGS(timeout=20).text(query, max_results=max_results, backend=backend)
    except Exception as exc:
        # DDGS can wrap its last engine exception as an argument, without
        # exception chaining. Raw messages can contain the entire request URL.
        cause = exc.args[0] if exc.args and isinstance(exc.args[0], Exception) else exc
        reason = "provider_error"
        if isinstance(exc, TimeoutException) or isinstance(cause, TimeoutError):
            reason = "timeout"
        elif isinstance(cause, RatelimitException):
            reason = "rate_limited"
        elif type(exc) is DDGSException and exc.args == ("No results found.",):
            reason = "no_results"
        logging.getLogger(__name__).warning(
            "Search failed backend=%s reason=%s exception=%s cause=%s max_results=%d elapsed_ms=%d",
            backend, reason, type(exc).__name__, type(cause).__name__, max_results,
            round((monotonic() - started) * 1000),
        )
        if reason == "no_results":
            return []
        raise
