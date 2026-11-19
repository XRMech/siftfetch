"""Fixed browser-side operations for the offline live viewport."""

# These functions operate on sanitized snapshot markup with page scripts
# disabled. Only host-produced integer indices and action kinds cross into JS.
_CONTROLS = r"""
function exposed(el) {
    if (!el || el.closest('[hidden], [aria-hidden="true"], [data-sift-hidden]')) return false;
    for (let ancestor = el; ancestor; ancestor = ancestor.parentElement) {
        if (ancestor.localName === 'details' && !ancestor.open) {
            const summary = ancestor.querySelector(':scope > summary');
            if (!summary || !summary.contains(el)) return false;
        }
    }
    return true;
}
function controls() {
    const result = [];
    const top = window.scrollY, height = window.innerHeight;
    if (top > 1) result.push({kind: 'previous', index: 0, label: 'Previous screen'});
    if (top + height + 1 < document.scrollingElement.scrollHeight)
        result.push({kind: 'next', index: 0, label: 'Next screen'});
    const ids = new Map();
    for (const el of document.querySelectorAll('[id]'))
        ids.set(el.id, ids.has(el.id) ? null : el);
    const nodes = document.querySelectorAll('details, [role="tab"]');
    for (let index = 0; index < nodes.length; ++index) {
        const node = nodes[index];
        let label, target, kind;
        if (node.localName === 'details' && !node.open) {
            kind = 'details';
            label = node.querySelector(':scope > summary');
            target = node;
        } else if (node.getAttribute('role') === 'tab') {
            kind = 'tab';
            label = node;
            target = ids.get(node.getAttribute('aria-controls'));
            if (!target || target.getAttribute('role') !== 'tabpanel' || !target.hidden) continue;
            const labelled = target.getAttribute('aria-labelledby');
            if (labelled && (!node.id || ids.get(node.id) !== node || labelled !== node.id)) continue;
        } else continue;
        if (!exposed(label)) continue;
        const box = label.getBoundingClientRect();
        if (!box.width || !box.height || box.bottom <= 0 || box.top >= height
            || box.right <= 0 || box.left >= innerWidth) continue;
        const hiddenLabel = label.querySelector('[hidden], [aria-hidden="true"], [data-sift-hidden]');
        const name = (hiddenLabel ? '(partly hidden label)' : label.innerText) || kind;
        result.push({kind, index, label: name.slice(0, 160), labelClipped: name.length > 160, target});
        if (result.length === 65) break;
    }
    return result;
}
"""


INVENTORY = "() => {" + _CONTROLS + r"""
    const actions = controls();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const range = document.createRange();
    const text = [];
    let chars = 0, clipped = false;
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (!node.textContent.trim() || node.parentElement.closest('style') || !exposed(node.parentElement)) continue;
        range.selectNodeContents(node);
        const boxes = range.getClientRects();
        let visible = false;
        for (const r of boxes) {
            if (r.width && r.height && r.bottom > 0 && r.top < innerHeight
                && r.right > 0 && r.left < innerWidth) { visible = true; break; }
        }
        if (!visible) continue;
        const value = node.textContent.trim();
        text.push(value.slice(0, 30000 - chars));
        chars += value.length + 1;
        if (chars > 30000) { clipped = true; break; }
    }
    return {text: text.join('\n'), clipped, actionsClipped: actions.length > 64 || actions.some(a => a.labelClipped),
            actions: actions.slice(0, 64).map(({kind,index,label}) => ({kind,index,label}))};
}"""


APPLY = "([kind,index]) => {" + _CONTROLS + r"""
    const action = controls().find(a => a.kind === kind && a.index === index);
    if (!action) return false;
    if (kind === 'next' || kind === 'previous')
        window.scrollBy({top: (kind === 'next' ? 1 : -1) * innerHeight * 0.85, behavior: 'instant'});
    else {
        if (kind === 'details') action.target.open = true;
        else if (kind === 'tab') {
            action.target.hidden = false;
            action.target.removeAttribute('aria-hidden');
        } else return false;
        action.target.scrollIntoView({block:'start', behavior:'instant'});
    }
    return true;
}"""
