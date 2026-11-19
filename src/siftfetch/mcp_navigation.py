"""Single-call navigation adapters for the synchronous MCP tool worker."""
import asyncio
from itertools import islice
from typing import Literal

from siftfetch import pagination, panels
from siftfetch.live_navigation import LiveNavigation
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable


NavigationMode = Literal["panels", "next", "viewport"]


def _index(items, ordinal):
    if ordinal > len(items):
        raise ValueError("Selection unavailable in the current inventory")
    return items[ordinal - 1]


def _entry(read):
    return {"content": read.content, "truncated": read.truncated}


async def _viewport(flow, handle, selections):
    async with LiveNavigation(flow, handle) as live:
        current = await live.view()
        for ordinal in selections:
            control = _index(current.controls, ordinal)
            current = await live.select(control.id)
        return {"status": "ok", "control_count": len(current.controls), **_entry(current)}


def navigate_once(url: str, mode: NavigationMode, selections: list[int] | None = None,
                  expected_next_url: str | None = None) -> dict:
    """Open a fresh anonymous flow and close it before returning marked evidence."""
    if mode not in ("panels", "next", "viewport"):
        raise ValueError("Unknown navigation mode")
    choices = [] if selections is None else selections
    if (not isinstance(choices, list) or len(choices) > (1 if mode == "next" else 4)
            or any(type(n) is not int or not 1 <= n <= (32 if mode == "next" else 64)
                   for n in choices)):
        raise ValueError("Invalid navigation selections")
    if mode == "next" and choices:
        if not isinstance(expected_next_url, str) or not 1 <= len(expected_next_url) <= 4096:
            raise ValueError("Supply the exact next-page URL observed in the inventory")
    elif expected_next_url is not None:
        raise ValueError("An expected URL applies only when following a next-page link")
    if mode == "panels" and len(set(choices)) != len(choices):
        raise ValueError("Select each panel at most once")

    with ResearchFlow() as flow:
        first = flow.fetch(url)
        if first.handle is None:
            return {"status": "call_only", **_entry(first)}
        handle = first.handle
        try:
            if mode == "viewport":
                return asyncio.run(_viewport(flow, handle, choices))
            inventory = (pagination.pagination_inventory(flow, handle) if mode == "next"
                         else panels.panel_inventory(flow, handle))
            result = {"status": "ok", "control_count": len(inventory.ids)}
            if not choices:
                return {**result, **_entry(inventory)}
            selected = [_index(inventory.ids, ordinal) for ordinal in choices]
            if mode == "panels":
                result["panels"] = [_entry(panels.read_panel(flow, handle, key)) for key in selected]
                return result
            # The caller's URL is only a comparison value. follow_next resolves
            # the issued capture-local ID and performs its usual per-hop checks.
            item = flow._capture(handle)
            if not any(key == selected[0] and target == expected_next_url
                       for key, target in islice(pagination._entries(item), len(inventory.ids))):
                raise ValueError("Selected next-page destination changed or did not match")
            return {**result, **_entry(pagination.follow_next(flow, handle, selected[0]))}
        except SnapshotUnavailable:
            return {"status": "capture_unavailable", **_entry(first)}
