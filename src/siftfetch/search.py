"""Web search via DDGS (no API key required)."""

from ddgs import DDGS

from siftfetch import egress_policy
from siftfetch.egress_policy import EgressDenied


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
        List of dicts with keys: title, url, snippet.

    Raises:
        EgressDenied: The query carries a protected value; nothing was sent.
    """
    decision = egress_policy.check_search(query)
    if decision.action != "allow":
        raise EgressDenied(decision)

    max_results = max(1, min(max_results, 20))

    ddgs = DDGS(timeout=20)
    raw = ddgs.text(query, max_results=max_results)

    results = []
    for item in raw:
        results.append({
            "title": item.get("title", ""),
            "url": item.get("href", ""),
            "snippet": item.get("body", ""),
        })
    return results
