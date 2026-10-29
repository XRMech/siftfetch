"""Static no-token gate scans even skipped tests, without invoking an agent."""
import ast
from pathlib import Path
import re

MODEL_MODULES = {'openai', 'anthropic', 'litellm', 'cohere', 'google.generativeai', 'google.genai',
                 'vertexai', 'boto3', 'bedrock', 'ollama', 'mistralai', 'groq'}
AGENT_BINARY = re.compile(r'(?i)(?:^|[\\/\s"\x27])(claude|codex|gemini)(?:\.(?:exe|cmd|bat))?(?=$|[\s"\x27])')


def violations(source):
    tree = ast.parse(source)
    assignments = {}
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update({a.asname or a.name: a.name for a in node.names})
        if isinstance(node, ast.ImportFrom):
            aliases.update({a.asname or a.name: (node.module or '') + '.' + a.name for a in node.names})
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
    def strings(node, seen=None):
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name) and node.id not in seen:
            for value in assignments.get(node.id, []):
                yield from strings(value, seen | {node.id})
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value
        else:
            for child in ast.iter_child_nodes(node):
                yield from strings(child, seen)
    errors = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = ([a.name for a in node.names] if isinstance(node, ast.Import) else
                       [node.module or '', *[(node.module or '') + '.' + a.name for a in node.names]])
            if any(m == banned or m.startswith(banned + '.') for m in modules for banned in MODEL_MODULES):
                errors.append('model SDK import')
        if isinstance(node, ast.Call):
            func = ast.unparse(node.func)
            first, dot, rest = func.partition('.')
            func = aliases.get(first, first) + (dot + rest if dot else '')
            if func.endswith(('import_module', '__import__')) and any(s in MODEL_MODULES for a in node.args for s in strings(a)):
                errors.append('dynamic model SDK import')
            if func.split('.')[-1] in {'run', 'Popen', 'call', 'check_call', 'check_output', 'system', 'popen', 'spawn', 'spawnv', 'execv', 'execvp', 'create_subprocess_exec', 'create_subprocess_shell'}:
                args = list(node.args[:1]) + [k.value for k in node.keywords if k.arg in ('args', 'command', 'executable')]
                if any(AGENT_BINARY.search(s) for a in args for s in strings(a)):
                    errors.append('agent CLI launch')
    return errors


def test_suite_never_imports_model_sdks_or_launches_agents():
    for path in Path(__file__).parent.rglob('*.py'):
        assert not violations(path.read_text(encoding='utf-8-sig')), path.name


def test_guard_detects_skipped_and_aliased_launches():
    samples = ['import anthropic', 'from openai import Client',
               'from google import genai',
               'from subprocess import run as launch\nlaunch(["codex", "exec"])',
               'import subprocess as sp\ncmd = ["codex", "exec"]\nsp.run(cmd)',
               '@pytest.mark.skip\ndef test_bad():\n    subprocess.run(["claude", "-p", "test"])',
               'os.system("gemini prompt")', 'importlib.import_module("google.genai")']
    assert all(violations(sample) for sample in samples)
    assert not violations('subprocess.run([sys.executable, "-m", "siftfetch.hook"])')
