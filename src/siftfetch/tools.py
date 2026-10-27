"""SiftFetch's guarded web tools as plain functions, for use as a library.

Every page goes the same way: fetch (each hop checked by the privacy policy
in the transport), clean, escape and grade for injection patterns, then wrap
in the untrusted-content envelope. Pages graded high-risk are quarantined by
``fetch_and_save_sync``, never saved.

This module does not import the MCP SDK, so a project on any MCP version can
call these functions directly; ``siftfetch.server`` only moves them off the
event loop. Callers that run their own server use ``guarded`` to turn
network failures into the same one-line results the MCP tools return.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from ddgs.exceptions import DDGSException, TimeoutException as SearchTimeout

from siftfetch import browser_fetch, injection_scan, saving
from siftfetch.cleaner import (
    _JS_PAGE_WORDS,
    _word_count,
    alternate_source_urls,
    api_payload_to_markdown,
    clean_html,
    json_to_markdown,
    present_markdown,
    site_api_urls,
)
from siftfetch.downloader import download_to_staging as _download_to_staging
from siftfetch.downloader import DownloadRejected
from siftfetch.fetcher import bot_wall, fetch, list_available_sessions
from siftfetch.search import search_web as _search_web


def _browser_read(url, window, max_chars, offset, mode, section, extract):
    """Read a page in a real browser; returns (markdown, html), or None when
    the read could not happen or the challenge never cleared."""
    try:
        page = browser_fetch.read_page(url, window=window)
    except browser_fetch.BrowserFetchUnavailable:
        return None
    if page.challenged:
        return None
    header = (
        "*[Read with a real browser (fresh profile, no logins); a plain "
        "fetch of this page is refused or not attempted.]*\n\n"
    )
    out = clean_html(page.html, url=page.url, max_chars=max_chars, offset=offset,
                     mode=mode, section=section, extract=extract)
    return injection_scan.PreparedText(header + out), page.html


def _wall_recovery(url, status, max_chars, offset, mode, section, extract):
    """A bot wall answered instead of the page: try the site's official API,
    then a real-browser read if the owner turned that on."""
    parts = []
    for api_url in site_api_urls(url):
        try:
            text = api_payload_to_markdown(fetch(api_url).text, api_url)
        except Exception:
            continue
        if _word_count(text) > _JS_PAGE_WORDS:
            parts.append(text)
    if parts:
        header = (
            f"*[RECOVERED via official API: the page answered with a bot "
            f"wall (HTTP {status}). Content below came from the site's API.]*\n\n"
        )
        return present_markdown(header + "\n\n---\n\n".join(parts), max_chars=max_chars,
                                offset=offset, mode=mode, section=section), ""
    if browser_fetch.wanted(url, walled=True):
        read = _browser_read(url, None, max_chars, offset, mode, section, extract)
        if read:
            return read
    return (
        f"*[BOT WALL: {url} answered with an anti-bot block (HTTP {status}) "
        f"instead of the page. No official API is known for this site, and "
        f"real-browser reads are off or could not get past it. Options: ask "
        f"the owner to turn on browser_fetch, or find the same content "
        f"elsewhere.]*"
    ), ""


def session_kind() -> str:
    """Only an explicit interactive registration enables attended behavior."""
    return "attended" if (os.environ.get("SIFTFETCH_ATTENDED") == "1" and
                           os.environ.get("AGENT_HEADLESS") != "1") else "unattended"


def fetch_url_raw(url, browser="none", max_chars=30000, offset=0, mode="content",
                  section=None, extract="auto", show_browser=False,
                  session_kind="unattended"):
    """Fetch and clean, unlabeled; returns (markdown, raw body of the page it
    came from). Pass both to ``label`` before showing the text to a model."""
    if show_browser or browser_fetch.wanted(url, walled=False):
        read = _browser_read(url, "visible" if show_browser else None,
                             max_chars, offset, mode, section, extract)
        if read:
            return read
    try:
        resp = fetch(url, browser=browser, session_kind=session_kind)
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if not bot_wall(status, exc.response.text):
            raise
        return _wall_recovery(url, status, max_chars, offset, mode, section, extract)
    if bot_wall(resp.status_code, resp.text):
        return _wall_recovery(url, resp.status_code, max_chars, offset, mode, section,
                              extract)
    out = clean_html(resp.text, url=url, max_chars=max_chars, offset=offset,
                     mode=mode, section=section, extract=extract)
    # Client-rendered pages carry no text in their HTML, so cleaning cannot
    # help. Follow the alternate sources instead: verified per-site rewrites
    # first, then conventional probes (.md/.txt/.json/llms.txt/print view).
    if "EXTRACTION WARNING" not in out:
        return out, resp.text
    tried = []
    for candidate in alternate_source_urls(url)[:8]:
        try:
            alt = fetch(candidate, browser=browser, session_kind=session_kind)
        except Exception as exc:
            tried.append(f"{candidate} ({type(exc).__name__})")
            continue
        body = alt.text or ""
        recovered = ""
        if candidate.endswith(".json") or body.lstrip()[:1] in "{[":
            recovered = json_to_markdown(body)
        if not recovered and _word_count(body) > _JS_PAGE_WORDS:
            recovered = clean_html(body, url=candidate, max_chars=0, extract=extract)
        if _word_count(recovered) > _JS_PAGE_WORDS:
            header = (
                f"*[RECOVERED via alternate source: the requested page is "
                f"client-rendered and its HTML held no text. Content below "
                f"came from {candidate} "
                f"({_word_count(recovered):,} words).]*\n\n"
            )
            return present_markdown(header + recovered, max_chars=max_chars,
                                    offset=offset, mode=mode, section=section), body
        tried.append(f"{candidate} (thin)")
    return out + (
        f"\n\n*[Alternate sources tried and rejected: {'; '.join(tried)}. "
        f"This page likely needs a real-browser read.]*"
    ), resp.text


def label(text: str, raw: str = ""):
    """Escape, flag and grade web text; hidden regions come from the raw page.
    Returns (labeled text, scan)."""
    hidden = injection_scan.hidden_texts(raw) if raw else []
    return injection_scan.scan_text(text, hidden)


def scan_record(scan) -> dict:
    """The grade fields worth storing next to a saved or held page."""
    return {
        "risk": scan.risk,
        "complete": scan.complete,
        "categories": list(scan.categories),
        "hidden_categories": list(scan.hidden_categories),
        "patterns_version": scan.patterns_version,
    }


def fetch_url_sync(url, browser="none", max_chars=30000, offset=0, mode="content",
                   section=None, extract="auto", show_browser=False,
                   session_kind="unattended") -> str:
    out, raw = fetch_url_raw(url, browser, max_chars, offset, mode, section, extract,
                             show_browser, session_kind)
    labeled, scan = label(out, raw)
    return injection_scan.envelope(labeled, url, scan)


def search_web_sync(query: str, max_results: int = 5) -> list[dict]:
    """search_web with every title and snippet escaped, flagged and graded."""
    results = []
    for item in _search_web(query, max_results=max_results):
        title, title_scan = injection_scan.scan_text(injection_scan.safe_metadata(item.get("title", "")))
        snippet, snip_scan = injection_scan.scan_text(item.get("snippet", ""))
        worst = max(title_scan.risk, snip_scan.risk, key=injection_scan.RISK_ORDER.index)
        results.append({
            "title": title,
            "url": injection_scan.safe_metadata(item.get("url", "")),
            "snippet": snippet,
            "provenance": "untrusted-web",
            "risk": worst,
        })
    return results


def fetch_and_save_sync(url, name, browser="none", overwrite=False, max_chars=0,
                        session_kind="unattended") -> dict:
    """Fetch and grade, then save -- or quarantine and save nothing."""
    resp = fetch(url, browser=browser, session_kind=session_kind)
    cleaned = clean_html(resp.text, url=url, max_chars=max_chars)
    labeled, scan = label(cleaned, resp.text)
    title = next((line[2:].strip() for line in labeled.split("\n") if line.startswith("# ")), "")
    if scan.quarantined:
        held = saving.quarantine(labeled, url, title, scan_record(scan), "fetch_and_save")
        return {**held, "saved": False,
                "reason": "page held for owner review; nothing was saved"}
    wrapped = injection_scan.envelope(labeled, url, scan)
    return saving.save(wrapped, url, name, scan_record(scan), overwrite=overwrite)


def download_sync(url: str, expect: str, max_bytes: int,
                  staging_dir: str | Path | None = None) -> dict:
    """Download into ``staging_dir`` (default: the SiftFetch data folder)."""
    target = Path(staging_dir) if staging_dir is not None else saving.data_dir()
    return _download_to_staging(url, target, expect, max_bytes=max_bytes)


def list_sessions_sync(kind: str | None = None) -> list[dict]:
    return list_available_sessions(kind or session_kind())


NETWORK_ERRORS = (httpx.TransportError, DDGSException, DownloadRejected)


def network_failure(exc: Exception, operation: str, url: str = "") -> str:
    """One labeled line for a network failure: timed out, could not resolve,
    connection refused, or a generic failure."""
    causes, seen = [], set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        causes.append(current)
        current = current.__cause__ or current.__context__
    messages = " ".join(str(c).lower() for c in causes)
    if (any(isinstance(c, (httpx.TimeoutException, SearchTimeout, TimeoutError)) for c in causes)
            or isinstance(exc, DownloadRejected) and exc.reason == "timeout"
            or "timed out" in messages or "timeout" in messages):
        detail = "timed out"
    elif (any(isinstance(c, socket.gaierror) for c in causes)
          or any(word in messages for word in ("could not resolve", "getaddrinfo", "name or service not known", "nodename nor servname"))):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        detail = "could not resolve " + (injection_scan.safe_metadata(host) if host else "the service host")
    elif (any(isinstance(c, ConnectionRefusedError) or getattr(c, "errno", None) in (61, 111, 10061) for c in causes)
          or any(word in messages for word in ("connection refused", "actively refused", "10061"))):
        detail = "connection refused"
    else:
        detail = "connection failed" if isinstance(exc, httpx.TransportError) else "service request failed"
    return f"{operation} failed (network_error): {detail}."


def guarded(call, operation: str, url: str = ""):
    """Run ``call``; a network failure becomes ``network_failure``'s line.
    Policy denials and download rejections other than timeouts propagate."""
    try:
        return call()
    except NETWORK_ERRORS as exc:
        if isinstance(exc, DownloadRejected) and exc.reason != "timeout":
            raise
        return network_failure(exc, operation, url)
