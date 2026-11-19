"""Bounded section evidence for external directions; never execute page text."""
import re


REASONS = {
    "external_execution": "asks an agent to execute or install software",
    "external_submission": "asks an agent to submit information to an external service",
    "remote_instructions": "asks the reader to adopt remote skills or instructions",
    "instruction_file_change": "asks an agent to change project instruction files",
    "workflow_direction": "asks an agent to change its answer or research workflow",
}
_AUDIENCE = re.compile(r"\b(?:AI agents?|agents?|assistants?|LLMs?|Claude|Codex|ChatGPT)\b", re.I)
_INTRO = re.compile(r"^(?:(?:note|instructions?|feedback) (?:to|for) )?(?:AI agents?|agents?|assistants?|LLMs?)\s*[:,-]|\b(?:if you are|attention|for) (?:an? )?(?:AI |coding )?(?:agent|assistant|LLM)\b", re.I)
_COMMAND = re.compile(r"^(?:(?:AI )?(?:agents?|assistants?)\s*:\s*)?(?:(?:you )?(?:must|should|need to) |please )?(?:use|run|execute|install|send|submit|post|perform|download|fetch|read|follow|adopt|apply|add|append|write|edit|update|include|answer|report|open)\b|\b(?:you must|you should|you need to|then|please)\s+(?:run|send|submit|follow|install|fetch|add|include)\b", re.I)
_REMOTE = re.compile(r"\b(?:follow|obey|adopt|apply)\b.{0,160}(?:https?://|\b(?:remote|linked|downloaded)\b.{0,40}\b(?:skills?|instructions?|prompts?)\b)|\b(?:download|fetch|read)\b.{0,160}\b(?:skills?|instructions?|AGENTS\.md)\b.{0,100}\b(?:follow|obey|adopt|apply)\b", re.I)
_DESCRIPTION = re.compile(r"^(?:the |an? |this )?(?:example|attack|payload|article|documentation|researcher)\b|^(?:do not|never|don't)\b", re.I)


def direction_hits(text):
    """Keep agent audience for <= 2400 chars/24 lines, within its section.

    Fences never establish audience. Code contributes only under an explicit
    agent audience; quoted research and negative advice do not activate it.
    Original offsets are returned, including the supporting audience span.
    """
    audience = None
    level = 7
    age = 0
    fence = None
    position = 0
    for raw in text.splitlines(keepends=True):
        start, position = position, position + len(raw)
        line = raw.strip()
        age += 1
        if audience is not None and (position - audience > 2400 or age > 24):
            audience = None
        marker = re.match(r"^(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)", line) if fence is None else None
        if heading and len(heading[1]) <= level:
            audience = None
        prose = re.sub(r"^(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+)", "", line).strip('`* ')
        if line.startswith('>') or _DESCRIPTION.search(prose):
            continue
        # Flattened HTML headings can lose their Markdown prefix.
        title = len(prose) <= 100 and re.fullmatch(r"(?:AI |Coding )?Agent(?:s|[- ]Assisted)? (?:Instructions|Setup|Feedback)", prose, re.I)
        indented = raw.startswith(("    ", "\t"))
        if fence is None and not indented and _AUDIENCE.search(prose) and (heading or title or _INTRO.search(prose)):
            audience, age = start, 0
            level = len(heading[1]) if heading else 7
        command = bool(_COMMAND.search(prose))
        remote = command and bool(_REMOTE.search(prose)) and bool(
            re.search(r"\b(?:skills?|instructions?|prompts?|AGENTS\.md)\b", prose, re.I)
            or re.search(r"\b(?:download|fetch|read)\b.{0,100}\bfollow\b", prose, re.I))
        if audience is None and not remote:
            continue
        if (fence is not None or indented) and audience is None:
            continue
        categories = set()
        if remote:
            categories.add("remote_instructions")
        if audience is not None:
            if command and re.search(r"\b(?:run|execute|install|npx|npm|pip|curl|provision)\b", prose, re.I) or re.match(r"(?:npx|npm install|pip install)\s", prose, re.I):
                categories.add("external_execution")
            if command and re.search(r"\b(?:send|submit|post|report|HTTP GET)\b", prose, re.I) or re.match(r"(?:GET|POST)\s+https?://", prose):
                categories.add("external_submission")
            if command and re.search(r"\b(?:add|append|write|edit|update)\b", prose, re.I) and re.search(r"\b(?:AGENTS|CLAUDE|GEMINI)\.md\b", prose, re.I):
                categories.add("instruction_file_change")
            if re.search(r"\b(?:when answering|before (?:you )?answer|your (?:answer|response)|follow-up question)\b", prose, re.I) and re.search(r"\b(?:fetch|include|say|open|read|use|must)\b", prose, re.I):
                categories.add("workflow_direction")
        for category in sorted(categories):
            yield (audience if audience is not None else start, position - len(raw) + len(raw.rstrip()), category)
