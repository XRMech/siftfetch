"""Select a declared next-page URL from an anonymous public HTML capture."""
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import blake2s
from itertools import islice
import re
import time
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
import httpx

from siftfetch import fetcher, tools
from siftfetch.research_flow import PageRead, ResearchFlow, _eligible, _evidence


_LIMIT = 32
_PAGE_FIELD = re.compile(r"(?:page|p|offset|start|limit|per_page)=[0-9]{1,12}", re.ASCII)


@dataclass(frozen=True)
class PaginationInventory:
    ids: tuple[str, ...]
    content: str
    truncated: bool


def _allowed(url, origin):
    # Compare origins as interpreted by the HTTP transport. Refuse ambiguous
    # spellings and URL credentials before resolution or any request.
    if len(url) > 4096 or "\\" in url or any(ord(char) < 32 or ord(char) == 127 for char in url):
        return False
    try:
        parts = urlsplit(url)
        target = httpx.URL(url)
        if (target.scheme != "https" or target.host != origin.host or target.port != origin.port
                or parts.username is not None or parts.fragment or parts.port == 0):
            return False
    except (ValueError, httpx.InvalidURL):
        return False
    fields = parts.query.split("&") if parts.query else []
    return (all(_PAGE_FIELD.fullmatch(field) for field in fields)
            and len({field.partition("=")[0] for field in fields}) == len(fields))


def _entries(item):
    soup = BeautifulSoup(item.html, "lxml")
    for inert in soup.find_all(["script", "template", "noscript", "iframe", "svg", "math", "object", "form"]):
        inert.decompose()
    base = soup.find("base", href=True)
    try:
        base_url = urljoin(item.url, base["href"]) if base else item.url
    except ValueError:
        return
    origin = httpx.URL(item.url)
    seen = set()
    base_target = soup.find("base", target=True)
    default_target = base_target["target"] if base_target else "_self"
    for pos, el in enumerate(soup.find_all(["a", "link"], href=True)):
        rel = {token.lower() for token in el.get("rel", [])}
        if ("next" not in rel or "external" in rel or el.has_attr("download") or el.has_attr("ping")
                or any(name.lower().startswith("on") for name in el.attrs)):
            continue
        target = el.get("target", default_target if el.name == "a" else "_self")
        if target.strip().lower() not in ("", "_self"):
            continue
        href = el["href"].strip()
        if not href or href.startswith("#"):
            continue
        try:
            url = urljoin(base_url, href)
        except ValueError:
            continue
        if not _allowed(url, origin) or url in seen or httpx.URL(url) == origin:
            continue
        seen.add(url)
        control = blake2s(f"page/{item.handle}/{pos}".encode(), digest_size=12).hexdigest()
        yield control, url


def pagination_inventory(flow: ResearchFlow, handle: str) -> PaginationInventory:
    """List up to 32 same-origin static next links locally, with their destinations."""
    with flow._operations:
        item = flow._capture(handle)
        entries = list(islice(_entries(item), _LIMIT + 1))
        clipped = len(entries) > _LIMIT
        entries = entries[:_LIMIT]
        text = "\n".join(f"{key}  {url}" for key, url in entries) or "No supported next-page link."
        content = _evidence(text, item.url, "pagination_inventory", item.initial_scan, complete=not clipped)
        return PaginationInventory(tuple(key for key, _ in entries), content, clipped)


def follow_next(flow: ResearchFlow, handle: str, link_id: str) -> PageRead:
    """Follow one indexed link anonymously and return the cleaned, labeled next page."""
    with flow._operations:
        item = flow._capture(handle)
        for key, target in islice(_entries(item), _LIMIT):
            if key == link_id:
                break
        else:
            raise KeyError("Next-page link unavailable")
        origin = httpx.URL(item.url)

        def validate(url):
            if not _allowed(url, origin):
                raise ValueError("Pagination requires a supported same-origin HTTPS destination")

        deadline = time.monotonic() + fetcher._TOTAL_SECONDS
        with fetcher.checked_response(target, stream=True, public_only=True,
                                      deadline=deadline, validate_hop=validate) as response:
            mime = response.headers.get("Content-Type", "").partition(";")[0].strip().lower()
            if (response.status_code != 200 or mime != "text/html" or "content-range" in response.headers
                    or "attachment" in response.headers.get("Content-Disposition", "").lower()):
                raise ValueError("Expected a complete HTML next page")
            response._content = fetcher._read_capped(response, deadline)
            raw = response.text
            if "\x00" in raw[:4096] or raw.startswith("%PDF-"):
                raise ValueError("Expected HTML next-page content")
            source = str(response.url)
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds") if _eligible(response) else None
        text = tools.clean_html(raw, url=source)
        tools._mark_public_page(text, response)
        return flow._finish_read(text, raw, source, stamp, "auto")
