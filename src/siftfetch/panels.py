"""Read native disclosures and local ARIA tab panels from a public HTML capture."""
from dataclasses import dataclass
from hashlib import blake2s
from itertools import islice

from bs4 import BeautifulSoup, Tag

from siftfetch.cleaner import clean_html
from siftfetch.hidden_text import BROWSER_ATTR, iter_hidden_regions
from siftfetch.research_flow import PageRead, ResearchFlow, _evidence


_MAX_PANELS = 64
_MAX_LABEL = 160
_MAX_CHARS = 30_000


@dataclass(frozen=True)
class PanelInventory:
    ids: tuple[str, ...]
    content: str
    truncated: bool


def _unique(nodes, attribute):
    """Index single ID references, leaving ambiguous keys unavailable."""
    index = {}
    for node in nodes:
        value = node.get(attribute, "")
        tokens = value.split()
        if len(tokens) == 1 and (attribute != "id" or value == tokens[0]):
            key = tokens[0]
            index[key] = None if key in index else node
    return index


def _entries(item):
    soup = BeautifulSoup(item.html, "lxml")
    ids = _unique(soup.find_all(id=True), "id")
    for inert in soup.find_all(["template", "script", "noscript", "iframe", "svg", "math", "object"]):
        inert.decompose()
    # Retain ancestor and stylesheet hiding when the chosen subtree is isolated.
    for region, reason in iter_hidden_regions(soup):
        region[BROWSER_ATTR] = reason
    reverse = _unique(soup.find_all(role=lambda role: role and role.strip().lower() == "tabpanel"),
                      "aria-labelledby")
    for pos, node in enumerate(soup.find_all(True)):
        if node.name == "details":
            target, label, kind = node, node.find("summary", recursive=False), "details"
        elif node.get("role", "").strip().lower() == "tab":
            if node.has_attr("aria-controls"):
                target = ids.get(node["aria-controls"].strip())
                if target is None or target.attrs is None or target.get("role", "").strip().lower() != "tabpanel":
                    continue
                labels = target.get("aria-labelledby", "").split()
                if labels and (node.get("id") not in labels or ids.get(node.get("id")) is not node):
                    continue
            else:
                tab_id = node.get("id")
                target = reverse.get(tab_id)
                if target is None or ids.get(tab_id) is not node:
                    continue
            label, kind = node, "tab"
        else:
            continue
        panel_id = blake2s(f"panel/{item.handle}/{pos}".encode(), digest_size=12).hexdigest()
        yield panel_id, kind, label, target


def _title(label: Tag | None):
    if label is None:
        return "Details"
    if (label.has_attr(BROWSER_ATTR) or label.find_parent(attrs={BROWSER_ATTR: True}) is not None
            or label.find(attrs={BROWSER_ATTR: True}) is not None):
        return "(hidden label)"
    text = label.get("aria-label") or label.get_text(" ", strip=True)
    return " ".join(text.split())


def panel_inventory(flow: ResearchFlow, handle: str) -> PanelInventory:
    """List capture-local panel IDs and enveloped labels in document order."""
    with flow._operations:
        item = flow._capture(handle)
        ids, lines = [], []
        clipped = False
        for panel_id, kind, label, _ in _entries(item):
            if len(ids) >= _MAX_PANELS:
                clipped = True
                break
            title = _title(label)
            clipped |= len(title) > _MAX_LABEL
            ids.append(panel_id)
            lines.append(f"{panel_id}  {kind}  {title[:_MAX_LABEL]}")
        text = "\n".join(lines) or "No supported static panels."
        content = _evidence(text, item.url, "panel_inventory", item.initial_scan, complete=not clipped)
        return PanelInventory(tuple(ids), content, clipped)


def read_panel(flow: ResearchFlow, handle: str, panel_id: str, *, max_chars=30_000) -> PageRead:
    """Return cleaned, labeled content already present in one selected panel."""
    if type(max_chars) is not int or not 1 <= max_chars <= _MAX_CHARS:
        raise ValueError(f"max_chars must be between 1 and {_MAX_CHARS}")
    with flow._operations:
        item = flow._capture(handle)
        for candidate, _, _, target in islice(_entries(item), _MAX_PANELS):
            if candidate == panel_id:
                break
        else:
            raise KeyError("Panel unavailable")
        hidden_parent = target.find_parent(attrs={BROWSER_ATTR: True})
        if hidden_parent is not None:
            target[BROWSER_ATTR] = hidden_parent[BROWSER_ATTR]
        # The surrounding main keeps nested documentation containers from
        # narrowing this explicitly selected fragment during extraction.
        raw = "<main>" + str(target) + "</main>"
        text = clean_html(raw, url=item.url, include_metadata=False, include_links=False,
                          max_chars=max_chars, extract="raw", fragment=True)
        content = _evidence(text, item.url, "read_panel", item.initial_scan,
                            complete=not text.truncated, raw=raw)
        return PageRead(content, handle, item.captured_at, text.truncated)
