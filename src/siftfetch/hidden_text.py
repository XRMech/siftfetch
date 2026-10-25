"""Find page text a human reader can't see, so it can be marked and graded.

A common injection hides its instructions in plain sight. The text stays on
the page, but it is colored like its background, sized to nothing, made
transparent, pushed off-screen or clipped away. A person sees a normal page,
while an agent reading the extracted text gets the hidden part too.

``hidden_regions`` finds those regions from the page's inline styles,
``<style>`` blocks and presentational attributes. ``clean_html`` marks them
inline, so the agent sees which text was hidden and how, and
``injection_scan`` grades instructions found in them more severely.

Static analysis can't see external stylesheets or styles set by scripts.
Real-browser reads (``browser_fetch``) close that gap: the browser computes
each element's final style and tags hidden text with ``BROWSER_ATTR``, which
this module reads like any other reason. A hostile page can still interfere
with a script run inside it, so this is detection, not a guarantee.

To avoid false alarms, where the background can't be known (a background
image or gradient), text color is not compared.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

BROWSER_ATTR = "data-sift-hidden"
MARK_MIN_WORDS = 3  # shorter hidden snippets (icons, "x") are graded but not marked
_CONTRAST_FLOOR = 1.25  # WCAG contrast ratio; 1.0 means identical colors
_TINY_FONT_PX = 2.0
_OFFSCREEN_PX = -500.0
_WHITE = (255.0, 255.0, 255.0, 1.0)

# Reasons that hide a whole subtree: a child can't undo them.
_SUBTREE = "subtree"
# Reasons that depend on inherited color or size, which a child can override.
_TEXT = "text"

_NAMED_COLORS = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0),
    "green": (0, 128, 0), "blue": (0, 0, 255), "yellow": (255, 255, 0),
    "gray": (128, 128, 128), "grey": (128, 128, 128), "silver": (192, 192, 192),
    "whitesmoke": (245, 245, 245), "snow": (255, 250, 250), "ivory": (255, 255, 240),
    "ghostwhite": (248, 248, 255), "floralwhite": (255, 250, 240),
    "linen": (250, 240, 230), "beige": (245, 245, 220), "azure": (240, 255, 255),
    "aliceblue": (240, 248, 255), "mintcream": (245, 255, 250),
    "lightgray": (211, 211, 211), "lightgrey": (211, 211, 211),
    "gainsboro": (220, 220, 220), "darkgray": (169, 169, 169),
    "navy": (0, 0, 128), "maroon": (128, 0, 0), "orange": (255, 165, 0),
    "purple": (128, 0, 128), "teal": (0, 128, 128),
}
_DECL = re.compile(r"([\w-]+)\s*:\s*([^;]+)")
_RULE = re.compile(r"([^{}@]+)\{([^{}]*)\}")
_AT_BLOCK = re.compile(r"@[^{]+\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}")
_SIMPLE_SELECTOR = re.compile(r"^([a-z][\w-]*)?((?:[.#][\w-]+)*)$", re.IGNORECASE)
_LENGTH = re.compile(r"^(-?[\d.]+)(px|pt|em|rem|%)?$")


def _parse_color(value: str) -> tuple[float, float, float, float] | None:
    v = value.strip().lower().replace("!important", "").strip()
    if v == "transparent":
        return (0.0, 0.0, 0.0, 0.0)
    if v in _NAMED_COLORS:
        return (*map(float, _NAMED_COLORS[v]), 1.0)
    m = re.fullmatch(r"#([0-9a-f]{3,8})", v)
    if m:
        h = m.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) not in (6, 8):
            return None
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return (float(int(h[0:2], 16)), float(int(h[2:4], 16)), float(int(h[4:6], 16)), a)
    m = re.fullmatch(r"rgba?\(([^)]*)\)", v)
    if m:
        parts = [p for p in re.split(r"[\s,/]+", m.group(1)) if p]
        try:
            rgb = [float(p[:-1]) * 2.55 if p.endswith("%") else float(p) for p in parts[:3]]
            a = parts[3] if len(parts) > 3 else "1"
            alpha = float(a[:-1]) / 100 if a.endswith("%") else float(a)
        except ValueError:
            return None
        return (*rgb, alpha) if len(rgb) == 3 else None
    return None


def _luminance(rgb) -> float:
    def channel(c):
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(c) for c in rgb[:3])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a, b) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _declarations(text: str) -> dict[str, str]:
    return {k.lower(): v.strip() for k, v in _DECL.findall(text or "")}


def _style_rules(soup: BeautifulSoup) -> list[tuple[str | None, set[str], str | None, dict]]:
    """Simple-selector rules from <style> blocks: (tag, classes, id, declarations).

    Rules inside @media and other @-blocks are skipped, and so are compound
    selectors: matching them needs a CSS engine, which a browser read has.
    """
    rules = []
    for style in soup.find_all("style"):
        css = re.sub(r"/\*.*?\*/", "", style.get_text() or "", flags=re.DOTALL)
        css = _AT_BLOCK.sub("", css)
        for selectors, body in _RULE.findall(css):
            decls = _declarations(body)
            for selector in selectors.split(","):
                m = _SIMPLE_SELECTOR.match(selector.strip())
                if not m or not selector.strip():
                    continue
                parts = re.findall(r"([.#])([\w-]+)", m.group(2))
                classes = {name for kind, name in parts if kind == "."}
                ids = [name for kind, name in parts if kind == "#"]
                rules.append(((m.group(1) or "").lower() or None, classes,
                              ids[0] if ids else None, decls))
    return rules


def _own_style(el: Tag, rules) -> dict[str, str]:
    style: dict[str, str] = {}
    classes = set(el.get("class") or [])
    for tag, need, ident, decls in rules:
        if tag and tag != el.name:
            continue
        if need and not need <= classes:
            continue
        if ident and el.get("id") != ident:
            continue
        style.update(decls)
    style.update(_declarations(str(el.get("style") or "")))
    if el.name == "font" and el.get("color"):
        style.setdefault("color", str(el["color"]))
    if el.get("bgcolor"):
        style.setdefault("background-color", str(el["bgcolor"]))
    return style


def _px(value: str | None, parent_px: float) -> float | None:
    if not value:
        return None
    m = _LENGTH.match(value.strip().lower().replace("!important", "").strip())
    if not m:
        return None
    n, unit = float(m.group(1)), m.group(2) or "px"
    return {"px": n, "pt": n * 4 / 3, "em": n * parent_px, "%": n / 100 * parent_px,
            "rem": n * 16}[unit]


def _opacity(value: str | None) -> float:
    if not value:
        return 1.0
    v = value.replace("!important", "").strip()
    try:
        return float(v[:-1]) / 100 if v.endswith("%") else float(v)
    except ValueError:
        return 1.0


def _background(style: dict[str, str], inherited):
    """The background behind this element: a color, or None when unknowable."""
    shorthand = style.get("background", "")
    if "url(" in shorthand or "gradient" in shorthand or style.get("background-image", "none") != "none":
        return None
    for value in (style.get("background-color"), shorthand.split(" ")[0] if shorthand else None):
        color = _parse_color(value) if value else None
        if color and color[3] >= 0.5:
            return color
    return inherited


def _subtree_reason(el: Tag, style: dict[str, str], opacity: float) -> str | None:
    if el.get(BROWSER_ATTR):
        return str(el[BROWSER_ATTR])
    if el.name == "template" or el.has_attr("hidden"):
        return "hidden element"
    if style.get("display", "").startswith("none"):
        return "hidden by CSS (display: none)"
    if opacity <= 0.05:
        return "fully transparent (opacity)"
    position = style.get("position", "")
    if position.startswith(("absolute", "fixed")):
        for side in ("left", "top"):
            offset = _px(style.get(side), 16)
            if offset is not None and offset <= _OFFSCREEN_PX:
                return "positioned off-screen"
    indent = _px(style.get("text-indent"), 16)
    if indent is not None and indent <= _OFFSCREEN_PX:
        return "pushed off-screen (text-indent)"
    clip = style.get("clip", "").replace(" ", "")
    clip_path = style.get("clip-path", "").replace(" ", "")
    if re.match(r"rect\((0(px)?,?){4}\)|rect\((1px,?){4}\)", clip) or clip_path in (
            "inset(50%)", "inset(100%)", "circle(0)", "circle(0px)"):
        return "clipped to nothing"
    if re.search(r"scale\(0(\.0+)?\)", style.get("transform", "")):
        return "scaled to nothing"
    overflow = style.get("overflow", "")
    if overflow.startswith("hidden") and any(
            _px(style.get(p), 16) == 0 for p in ("height", "width", "max-height", "max-width")):
        return "zero-size box"
    return None


def _text_reason(color, background, font_px: float, visibility: str) -> str | None:
    if visibility.startswith(("hidden", "collapse")):
        return "hidden by CSS (visibility)"
    if font_px <= _TINY_FONT_PX:
        return f"font too small to read ({font_px:g}px)"
    if color is not None and color[3] <= 0.05:
        return "transparent text color"
    if color is not None and background is not None and _contrast(color, background) < _CONTRAST_FLOOR:
        return "text colored like its background"
    return None


def _own_text(el: Tag) -> bool:
    return any(isinstance(c, NavigableString) and not isinstance(c, Comment) and c.strip()
               for c in el.children)


def hidden_regions(soup: BeautifulSoup) -> list[tuple[Tag, str]]:
    """Elements whose text a human reader can't see, with the reason, in page order."""
    rules = _style_rules(soup)
    found: list[tuple[Tag, str]] = []
    root = soup.find("html") or soup

    def walk(el: Tag, color, background, font_px: float, opacity: float, visibility: str):
        style = _own_style(el, rules)
        opacity *= _opacity(style.get("opacity"))
        reason = _subtree_reason(el, style, opacity)
        if reason:
            if el.get_text(strip=True):
                found.append((el, reason))
            return
        color = _parse_color(style["color"]) if "color" in style else color
        background = _background(style, background)
        size = _px(style.get("font-size"), font_px)
        font_px = size if size is not None else font_px
        visibility = style.get("visibility", visibility)
        if _own_text(el):
            reason = _text_reason(color, background, font_px, visibility)
            if reason:
                found.append((el, reason))
                return
        for child in el.children:
            if isinstance(child, Tag) and child.name not in ("script", "style", "noscript"):
                walk(child, color, background, font_px, opacity, visibility)

    if isinstance(root, Tag):
        walk(root, (0.0, 0.0, 0.0, 1.0), _WHITE, 16.0, 1.0, "visible")
    return found


# Ordinary interface hiding: menus, dialogs, tabs and language pickers are
# hidden this way on most sites (47 regions on one news front page). These
# are marked only when they hold instruction-like text; every hidden region
# still counts toward the injection grade.
_UI_HIDING = ("hidden element", "hidden by CSS")


def concealed(reason: str) -> bool:
    """True for hiding that makes text look absent (color, size, position),
    False for ordinary interface hiding (display, visibility, hidden)."""
    return not reason.startswith(_UI_HIDING)


def mark_hidden(soup: BeautifulSoup) -> list[str]:
    """Mark hidden regions inline; returns the reason of each region marked.

    Concealed text (colored like its background, transparent, tiny,
    off-screen, clipped) is always marked. Interface hiding is marked only
    when the text holds instruction-like patterns. Regions shorter than
    MARK_MIN_WORDS are left unmarked: hidden labels and icons are everywhere.
    """
    from siftfetch.injection_scan import suspicious

    marked = []
    for el, reason in hidden_regions(soup):
        text = el.get_text(" ", strip=True)
        if len(text.split()) < MARK_MIN_WORDS:
            continue
        if not concealed(reason) and not suspicious(text):
            continue
        el.insert(0, NavigableString(f" [HIDDEN FROM READERS: {reason}] "))
        el.append(NavigableString(" [END HIDDEN] "))
        marked.append(reason)
    return marked


# Run in the page by browser_fetch after load. Tags each element whose text the
# reader can't see with BROWSER_ATTR, using the browser's computed styles, so
# external stylesheets and script-set styles are covered.
BROWSER_SCRIPT = r"""
(attr) => {
  const parse = (c) => {
    const m = c && c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  };
  const lum = (c) => {
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
  };
  const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const background = (el) => {
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage && cs.backgroundImage !== 'none') return null;
      const c = parse(cs.backgroundColor);
      if (c && c[3] >= 0.5) return c;
    }
    return [255, 255, 255, 1];
  };
  const opacity = (el) => { let o = 1; for (let e = el; e; e = e.parentElement) o *= Number(getComputedStyle(e).opacity); return o; };
  const width = document.documentElement.scrollWidth, height = document.documentElement.scrollHeight;
  let tagged = 0;
  for (const el of document.body ? document.body.querySelectorAll('*') : []) {
    if (el.closest('[' + attr + ']')) continue;
    const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const cs = getComputedStyle(el), r = el.getBoundingClientRect();
    let why = null;
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') why = 'hidden by CSS';
    else if (opacity(el) <= 0.05) why = 'fully transparent (opacity)';
    else if (parseFloat(cs.fontSize) <= 2) why = 'font too small to read';
    else if (r.width === 0 || r.height === 0) why = 'zero-size box';
    else if (r.right <= 0 || r.bottom <= 0 || r.left >= width || r.top >= height) why = 'positioned off-screen';
    else {
      const c = parse(cs.color), b = background(el);
      if (c && c[3] <= 0.05) why = 'transparent text color';
      else if (c && b && contrast(c, b) < 1.25) why = 'text colored like its background';
    }
    if (why && el.innerText !== undefined) { el.setAttribute(attr, why); tagged++; }
  }
  return tagged;
}
"""
