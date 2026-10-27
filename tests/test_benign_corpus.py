"""Ordinary agent work stays available with the example policy and lock on."""

import io
import json
import time
from pathlib import Path

import pytest

from siftfetch import egress_policy as ep, hook


COMMANDS = [
    "git status", "git status --short", "git log -5", "git log --oneline",
    "git diff", "git diff --stat", "git diff -- src", "git branch --show-current",
    "git show --stat HEAD", "git commit -m 'Fix parser'", "git ls-files",
    "npm test", "npm run build", "npm ci", "npm ls", "npx tsc --noEmit",
    "pip list", "pip show pytest", "python -m pytest -q", "python --version",
    "uv sync", "uv run pytest", "uv pip list", "uv --version",
    "rg TODO src", "rg --files src", "rg -n parser src", "grep -rn TODO src --include=*.py",
    "grep -o parser src/main.py", "findstr /s TODO src/*.py", "ls src", "ls .*",
    "cat src/main.py", "head -20 README.md", "tail -10 README.md", "wc -l README.md",
    "cp src/main.py backup.py", "mv backup.py copy.py", "mkdir output",
    "curl https://docs.python.org/3/", "curl -O https://docs.python.org/3/index.html",
    "tar -tf archive.tar -C output", "echo ready", "pwd", "date", "whoami",
    "Get-ChildItem src", "Get-Content src/main.py", "Copy-Item src/main.py backup.py",
    "Move-Item backup.py copy.py", "Select-String TODO src/main.py", "Get-Date",
]
CALLS = [("Bash", {"command": c}) for c in COMMANDS]
CALLS += [("mcp__agent_mail__list_sessions", {}),
          ("mcp__rag__search", {"query": "Python parser documentation"}),
          ("WebSearch", {"query": "Python standard library"})]


@pytest.mark.parametrize("tool,tool_input", CALLS)
def test_benign_call(tmp_path, monkeypatch, capsys, tool, tool_input):
    policy = tmp_path / "policy"
    policy.mkdir()
    examples = Path(__file__).resolve().parents[1] / "examples"
    (policy / "identifiers.json").write_bytes((examples / "identifiers.example.json").read_bytes())
    (policy / "config.json").write_text('{"guard_lock": true}', encoding="utf-8")
    monkeypatch.setenv("SIFTFETCH_HOME", str(policy))
    monkeypatch.setenv("SIFTFETCH_DATA", str(tmp_path / "data"))
    monkeypatch.setattr(ep, "_cached", None)
    payload = {"tool_name": tool, "tool_input": tool_input, "cwd": str(tmp_path)}
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
    start = time.perf_counter()
    assert hook.main() == 0
    assert time.perf_counter() - start < .2
    assert capsys.readouterr().out == ""
