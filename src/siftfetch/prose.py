"""Small Markdown prose iterator shared by heuristics and spotlighting."""
import re


def paragraphs(text):
    """Yield character ranges, excluding fenced/indented code and table rows."""
    start = None
    offset = 0
    fence = None
    table = False
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        table_line = re.sub(r"<\|[^>]*\|>", "", mask_inline(line)).strip()
        next_line = lines[index + 1].strip() if index + 1 < len(lines) else ""
        delimiter = re.fullmatch(r"\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?", next_line)
        table = "|" in table_line and (table or table_line.startswith("|") or bool(delimiter))
        excluded = bool(fence or marker or line.startswith(("    ", "\t")) or table)
        boundary = excluded or not line.strip() or re.match(r"^\s*(?:#{1,6} |[-+*] |\d+[.)] )", line)
        if boundary and start is not None:
            yield start, offset
            start = None
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
        if not excluded and line.strip() and start is None:
            start = offset
        offset += len(line)
        if start is not None and re.match(r"^ {0,3}#{1,6} ", line):
            yield start, offset
            start = None
    if start is not None:
        yield start, offset


def protected_inline(text):
    """Inline code and link destinations, which must not be rewritten."""
    return list(re.finditer(r"(`+).*?\1|\[HIDDEN FROM READERS:[^]]*\]|\[END HIDDEN\]|(?<=\]\()(?:(?:[^()\n]|\([^()\n]*\))*)(?=\))", text))


def mask_inline(text):
    for match in reversed(protected_inline(text)):
        text = text[:match.start()] + " " * len(match[0]) + text[match.end():]
    return text


def spotlight(text, mode):
    """Mark prose and flagged words without touching code or link targets."""
    if mode == "off":
        return text
    out, position = [], 0
    for start, end in paragraphs(text):
        out.append(text[position:start])
        block = text[start:end]
        protected = {i for match in protected_inline(block) for i in range(match.start(), match.end())}
        marked, flagged, i = [], False, 0
        while i < len(block):
            annotation = re.match(r"⟦(?:flagged:[^⟧]+|/flagged|U\+[0-9A-F]+)⟧", block[i:]) if block[i] == "⟦" else None
            if annotation:
                token = annotation[0]
                if token.startswith("⟦flagged:"):
                    flagged = True
                elif token == "⟦/flagged⟧":
                    flagged = False
                marked.append(token)
                i += len(token)
                continue
            char = block[i]
            if char == " " and i not in protected and (mode == "words" or flagged):
                char = "ˆ"
            marked.append(char)
            i += 1
        out.append("ˆ " + "".join(marked))
        position = end
    out.append(text[position:])
    return "".join(out)
