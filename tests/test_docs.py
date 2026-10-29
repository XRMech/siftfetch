"""Documentation contracts; offline and independent of private policy."""
import ast
from datetime import date
import json
from pathlib import Path
import re

from siftfetch import egress_policy as ep

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / name for name in ('README.md', 'SETUP.md', 'AGENTS.md', 'llms.txt', 'RELEASING.md', 'SECURITY.md')]
DOCS += sorted((ROOT / 'docs').rglob('*.md'))


def test_documentation_lint():
    for path in DOCS:
        text = path.read_text(encoding='utf-8')
        assert text.startswith('---\n'), path
        front, body = text[4:].split('\n---\n', 1)
        for field in ('topic', 'status', 'last-updated'):
            assert re.search(r'^' + field + r': .+$', front, re.M), (path, field)
        verified = re.search(r'^last-updated: (\d{4}-\d{2}-\d{2})$', front, re.M)
        assert verified and date.fromisoformat(verified[1]) <= date.today(), path
        router = path.name in ('README.md', 'SETUP.md', 'index.md')
        assert len(text) / 4 <= (440 if router else 1650), (path, len(text) / 4)
        assert not re.search(r'\b(today|yesterday|tomorrow|recently|last week|next week)\b', body, re.I), path
        fenced = False
        for line in body.splitlines():
            if line.startswith('```'):
                assert fenced or re.fullmatch(r'```[a-zA-Z0-9_+-]+', line), (path, line)
                fenced = not fenced
        assert not fenced, path
        for target in re.findall(r'\[[^\]\n]+\]\(([^)]+)\)', body):
            assert not re.match(r'[a-z]+://|[/\\]|[A-Za-z]:', target), (path, target)
            destination, _, anchor = target.partition('#')
            linked = (path.parent / destination).resolve()
            assert linked.is_file(), (path, target)
            assert linked.is_relative_to(ROOT), (path, target)
            if anchor:
                headings = re.findall(r'^#+ (.+)$', linked.read_text(encoding='utf-8'), re.M)
                assert anchor in [re.sub(r'[^\w -]', '', h.lower()).replace(' ', '-') for h in headings]


def test_documentation_covers_code_interfaces():
    combined = '\n'.join(p.read_text(encoding='utf-8') for p in DOCS)
    source = ROOT / 'src/siftfetch'
    public = ast.parse((source / 'tools.py').read_text(encoding='utf-8'))
    for node in public.body:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith('_'):
            assert node.name in combined, node.name
    server = ast.parse((source / 'server.py').read_text(encoding='utf-8'))
    for node in server.body:
        if isinstance(node, ast.AsyncFunctionDef) and any(ast.unparse(d).startswith('mcp.tool(') for d in node.decorator_list):
            assert node.name in combined, node.name
    for key in ep.CONFIG_KEYS | ep.SUBSTITUTE_KEYS:
        assert key in combined, key
    for path in source.glob('*.py'):
        text = path.read_text(encoding='utf-8-sig')
        for variable in re.findall(r'(?:os\.)?environ(?:\.get\(|\[)[\"\x27]([A-Z][A-Z_0-9]+)', text):
            assert variable in combined, variable
        for code in re.findall(r'(?:Decision\([\"\x27](?:allow|deny|ask)[\"\x27],\s*|DownloadRejected\()[\"\x27]([a-z_]+)', text):
            assert code in combined, code
        for code in re.findall(r'\((policy_protected|secret_file|guard_lock(?:_unknown)?|malformed_input|guard_error)\b', text):
            assert code in combined, code
    for code in ep._NEXT_STEP:
        assert code in combined, code


def test_init_templates_match_examples():
    for stem in ('config', 'exceptions', 'identifiers'):
        example = 'identifiers.empty.example.json' if stem == 'identifiers' else stem + '.example.json'
        shipped = ROOT / 'src/siftfetch/templates' / (stem + '.json')
        assert json.loads(shipped.read_text(encoding='utf-8')) == json.loads((ROOT / 'examples' / example).read_text())


def test_documented_markers_are_exact():
    text = (ROOT / 'docs/api/results.md').read_text(encoding='utf-8')
    for marker in ('⟦flagged:category⟧', '⟦/flagged⟧', '⟦U+202E⟧', 'ˆ'):
        assert marker in text


def test_documented_config_defaults_and_nested_fields():
    text = (ROOT / 'docs/configuration.md').read_text(encoding='utf-8')
    rows = {}
    for line in text.splitlines():
        if line.startswith('|'):
            cells = [c.strip().strip('`') for c in line.strip('|').split('|')]
            if len(cells) >= 2:
                for key in cells[0].split(', '):
                    rows[key] = cells[1]
    # Derive scalar/list defaults from actual config lookups; no duplicate registry.
    for module in ('egress_policy.py', 'tools.py', 'sightings.py'):
        tree = ast.parse((ROOT / 'src/siftfetch' / module).read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != 'get' or len(node.args) < 2:
                continue
            if not isinstance(node.args[0], ast.Constant) or node.args[0].value not in ep.CONFIG_KEYS:
                continue
            if isinstance(node.args[1], (ast.Constant, ast.List, ast.Dict)):
                default = ast.literal_eval(node.args[1])
                rendered = str(default).lower() if isinstance(default, bool) else str(default)
                assert rendered in rows[node.args[0].value], (node.args[0].value, rendered)
    for parent, keys in {'guard_lock': ['enabled', 'paths'],
                         'browser_fetch': ['mode', 'window', 'browser', 'max_per_minute', 'sites'],
                         'local_endpoints': ['scheme', 'host', 'port', 'service', 'allowed_ops'],
                         'substitute': ep.SUBSTITUTE_KEYS}.items():
        for key in keys:
            assert parent + '.' + key in rows
