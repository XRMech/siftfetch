"""Bounded, explainable reader-instruction signals (no model or execution)."""
import base64
import binascii
import codecs
import html
import re
from urllib.parse import unquote


_WEIGHTS = {"address": 2, "meta": 3, "mood": 2, "conceal": 3,
            "movement": 3, "authority": 3, "sensitive": 0}
_DESTINATION = re.compile(r"https?://|[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b(?:transcript|conversation|chat history)\b", re.I)
_DESCRIPTION = re.compile(
    r"^\s*(?:[>*#-]\s*)?(?:(?:the|an?|this)\s+)?"
    r"(?:attack(?:er|s)?|payload|injection|example|researcher|paper|documentation|article)\b"
    r".{0,160}\b(?:says?|writes?|asks?|tells?|contains?|containing|describes?|instructs?|demonstrates?|quotes?)\b", re.I)
_ACTIVATE = re.compile(r"\b(?:follow|obey|apply|execute|adopt|perform|treat)\b.{0,100}"
                       r"\b(?:below|above|following|instructions?|directive|quoted|quotation|code|block|task|binding)\b", re.I)
_CANDIDATE = re.compile(
    r"(?<![\w/+])(?:[A-Za-z0-9_+/\-]{24,}={0,2})(?![\w/+])|"
    r"(?<!\S)(?:[^\s<>%]{0,128}%[0-9a-fA-F]{2}[^\s<>]*)|"
    r"(?:\\u[0-9a-fA-F]{4})+|(?:&#(?:x[0-9a-fA-F]+|\d+);)+")
_DATA_URI = re.compile(r"data:[^\s<>\"')]+", re.I)
_MAX_DECODED_BYTES = 32768
_MAX_CANDIDATES = 128
_MAX_RUN = 8192


def _signals(text, compiled):
    """Return contributing signal names; isolated vocabulary cannot pass."""
    found = {name for name, pattern in compiled.items() if pattern.search(text)}
    # English verb/noun ambiguity: "your answer" is a meta-reference, not
    # imperative mood. Require a clause-initial command or an obligation.
    if "mood" in found:
        obligation = re.search(r"\b(?:must|shall|should|required to|do not|don't|always|never)\b", text, re.I)
        command = any(not m[0].isascii()
                      or m[0].lower() in {"debes", "debe", "envie", "revela", "envoyez", "doit", "devez", "musst", "sende", "zeige", "deve", "envia", "rivela", "invia"}
                      or not text[:m.start()].strip(' \t\r\n\"\'>*-')
                      or _ACTIVATE.search(text[:m.start()])
                      or re.search(r"[:,;]\s*(?:please\s+)?$|\b(?:please|then|and|to)\s+$", text[:m.start()], re.I)
                      for m in compiled["mood"].finditer(text))
        if not obligation and not command:
            found.remove("mood")
    if "movement" in found and not _DESTINATION.search(text):
        found.remove("movement")
    return found


def _reader_instruction(text, compiled):
    if not any(compiled[k].search(text) for k in ("meta", "conceal", "movement")):
        return False
    if _DESCRIPTION.search(text) and not _ACTIVATE.search(text):
        return False
    signals = _signals(text, compiled)
    # Sending a support request to an endpoint is ordinary product usage.
    # Movement needs a conversational object, an AI addressee, or private data.
    if "movement" in signals and not (
            "meta" in signals or "sensitive" in signals or re.search(r"\b(?:assistant|AI|agent|model|transcript|conversation|private|personal|credentials?|password|secret)\b", text, re.I)):
        signals.remove("movement")
    if "conceal" in signals and not ("meta" in signals or re.search(r"\b(?:assistant|AI|agent|model|as your own)\b", text, re.I)):
        signals.remove("conceal")
    return (bool(signals & {"meta", "conceal", "movement"})
            and bool(signals & {"mood", "authority"})
            and sum(_WEIGHTS[s] for s in signals) >= 5)


def _reader_hits(text, compiled):
    # Sentence-local evidence: an article's description does not immunize the
    # next sentence. Cap clauses to keep adversarial punctuation linear.
    hits = []
    if not any(compiled[k].search(text) for k in ("meta", "conceal", "movement")):
        return hits
    text = re.sub(r"\[(?:HIDDEN FROM READERS:[^]]*|END HIDDEN|ATTRIBUTE[^]]*|END ATTRIBUTE)\]", lambda m: " " * len(m[0]), text)
    for sentence in re.finditer(r"[^\n]+?(?:[.!?。！？](?=\s|$)|\n|$)", text):
        for offset in range(sentence.start(), sentence.end(), 1200):
            end = min(offset + 1200, sentence.end())
            if _reader_instruction(text[offset:end], compiled):
                offset += len(text[offset:end]) - len(text[offset:end].lstrip())
                end -= len(text[offset:end]) - len(text[offset:end].rstrip())
                hits.append((offset, end, "reader_directed_instruction"))
    return hits


def _decoded_candidates(text):
    """Yield original offsets and printable decodes; shared byte/attempt budget."""
    remaining, attempts = _MAX_DECODED_BYTES, 0
    # Mask data URIs before candidate discovery, including their base64 body.
    source = _DATA_URI.sub(lambda m: " " * len(m[0]), text)
    queue = [(source, None, 0)]
    while queue and remaining > 0 and attempts < _MAX_CANDIDATES:
        source, origin, depth = queue.pop(0)
        candidates = ((m.start(), m.end(), m[0], "auto") for m in _CANDIDATE.finditer(source))
        # Explicit transforms operate only on the nearby line, never the page.
        transforms = []
        for m in re.finditer(r"\b(?:rot13|rotate|reverse(?:d)?)\b[^\n:]{0,80}:\s*([^\n]{1,8192})", source, re.I):
            transforms.append((m.start(1), m.end(1), m[1], "reverse" if m[0].lower().startswith("revers") else "rot13"))
        from itertools import chain
        for start, end, run, kind in chain(candidates, transforms):
            attempts += 1
            if attempts > _MAX_CANDIDATES or remaining <= 0:
                return
            if len(run) > _MAX_RUN:
                continue
            values = []
            if kind == "reverse":
                values.append(run[::-1])
            elif kind == "rot13":
                values.append(codecs.decode(run, "rot_13"))
            else:
                if "%" in run:
                    values.append(unquote(run))
                if "&#" in run:
                    values.append(html.unescape(run))
                if "\\u" in run:
                    values.append(re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m[1], 16)), run))
                try:
                    if len(run) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]{24,}", run):
                        values.append(bytes.fromhex(run).decode("utf-8"))
                    else:
                        values.append(base64.b64decode(run + "=" * (-len(run) % 4), altchars=b"-_", validate=True).decode("utf-8"))
                except (ValueError, UnicodeError, binascii.Error):
                    pass
            for value in values:
                size = len(value.encode("utf-8", errors="replace"))
                if size > remaining:
                    return
                remaining -= size
                if value == run or not value or sum(c.isprintable() or c.isspace() for c in value) / len(value) < .95:
                    continue
                span = origin or (start, end)
                yield (*span, value)
                if depth < 1:
                    queue.append((value, span, depth + 1))
