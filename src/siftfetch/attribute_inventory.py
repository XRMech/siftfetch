"""Bounded page attribute evidence shared by rendering and injection grading."""
from dataclasses import dataclass
import json


@dataclass(frozen=True)
class AttributeInventory:
    text: str
    complete: bool

    @property
    def large(self):
        return len(self.text) > 4096


def collect_attributes(soup, *, remove_titles=False):
    """Bounded inventory before extraction discards non-visible carriers.

    Values are plain text, never HTML or executable JSON. Parser-decoded HTML
    entities are preserved for the normal scanner. Attribute presence alone
    does not change risk.
    """
    parts, remaining = [], 32768
    complete = True

    def add(label, value):
        nonlocal remaining, complete
        if not isinstance(value, str) or not value.strip():
            return
        if value.lstrip().lower().startswith("data:"):
            return
        if len(value) > remaining:
            complete = False
        if remaining == 0:
            return
        value = value[:remaining]
        remaining -= len(value)
        parts.append(f"[ATTRIBUTE {label}] {value} [END ATTRIBUTE]")

    for el in soup.find_all(True):
        for key, value in list(el.attrs.items()):
            if key in {"alt", "title", "aria-label", "aria-description", "placeholder"} or key.startswith("data-") and key != "data-sift-hidden":
                add(f"{el.name}.{key}", value)
                # Do not let markdownify repeat a title outside containment.
                if key == "title" and remove_titles:
                    del el.attrs[key]
        if el.name == "meta" and (el.get("name") or el.get("property")):
            add("meta.content", el.get("content"))
        if el.name in {"title", "desc"} and el.find_parent("svg"):
            add("svg." + el.name, el.get_text(" ", strip=True))
        if el.name == "script" and str(el.get("type", "")).lower() in {"application/ld+json", "application/json"}:
            raw = el.string or ""
            if len(raw) > 32768:
                add("script.json", raw)
                continue
            try:
                data = json.loads(raw)
            except (ValueError, RecursionError):
                add("script.json", raw)
                continue
            stack = [data]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(reversed(list(item.values())))
                elif isinstance(item, list):
                    stack.extend(reversed(item))
                else:
                    add("script.json", item)
    return AttributeInventory("\n\n".join(parts), complete)
