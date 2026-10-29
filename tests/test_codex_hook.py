import io
import json
import sys
import pytest
from siftfetch import hook
from test_reviewed_hook import invoke
from test_server import _link_dir


def patch(action, path, body=""):
    return f"*** Begin Patch\n*** {action} File: {path}\n{body}*** End Patch\n"


@pytest.mark.parametrize("action,body", [("Add", "+new\n"), ("Update", "@@\n-old\n+new\n"), ("Delete", "")])
def test_all_patch_operations(invoke, action, body):
    assert invoke("apply_patch", command=patch(action, "src/example.py", body)) is None
    for target in (str(invoke.policy / "config.json"), ".claude/settings.json", ".codex/config.toml", ".mcp.json"):
        assert invoke("apply_patch", command=patch(action, target, body))["permissionDecision"] == "deny"


def test_patch_moves_multifile_and_data_lines(invoke):
    assert invoke("apply_patch", command=patch("Update", "src/a.py", "*** Move to: .codex/config.toml\n"))["permissionDecision"] == "deny"
    assert invoke("apply_patch", command=patch("Update", ".codex/config.toml", "*** Move to: src/a.py\n"))["permissionDecision"] == "deny"
    command = "*** Begin Patch\n*** Add File: src/a.py\n+ok\n*** Delete File: .mcp.json\n*** End Patch"
    assert invoke("apply_patch", command=command)["permissionDecision"] == "deny"
    # A marker in newly added file content is data, not another path.
    assert invoke("apply_patch", command=patch("Add", "src/a.py", "+*** Delete File: .mcp.json\n")) is None
    assert invoke("apply_patch", command=patch("Update", "src/a.py", "*** Move to: src/b.py\n")) is None


@pytest.mark.parametrize("command", [None, {}, "", "not a patch", "*** Begin Patch\n*** End Patch",
    "*** Begin Patch\n*** Add File: \n+x\n*** End Patch",
    "*** Begin Patch\n*** Update File: src/a.py\n???\n*** End Patch",
    "*** Begin Patch\n*** Update File: src/a.py\n@@\n*** End Patch",
    "*** Begin Patch\n*** Add File: src/a.py\n+x\n*** Move to: .mcp.json\n*** End Patch"])
def test_bad_patches_fail_closed(invoke, command):
    result = invoke("apply_patch", command=command)
    assert result["permissionDecision"] == "deny" and "malformed_patch" in result["permissionDecisionReason"]


def test_patch_normalization_and_junction(invoke, tmp_path):
    for path in ("src/../.claude/settings.json", ".claude/settings.json::$DATA", ".claude/settings.json. "):
        assert invoke("apply_patch", command=patch("Delete", path))["permissionDecision"] == "deny"
    link = tmp_path / "alias"
    _link_dir(invoke.policy, link)
    assert invoke("apply_patch", command=patch("Delete", str(link / "config.json")))["permissionDecision"] == "deny"


def test_unknown_lock_stays_closed(invoke):
    (invoke.policy / "config.json").write_text("{broken")
    result = invoke("apply_patch", command=patch("Delete", ".mcp.json"))
    assert "guard_lock_unknown" in result["permissionDecisionReason"]


@pytest.mark.parametrize("tool,args,denied", [
    ("Bash", {"command": "cat src/example.py", "timeout_ms": 1000}, False),
    ("Bash", {"command": "cat .env", "timeout_ms": 1000}, True),
    ("Bash", {"command": "echo synthetic@mail.test"}, True),
    ("Bash", {"cmd": "cat .env"}, True),
    ("apply_patch", {"command": patch("Add", "src/a.py", "+ok\n")}, False),
    ("mcp__remote__request", {"body": {"email": "synthetic@mail.test"}}, True),
    ("mcp__remote__request", {"url": "http://127.0.0.1/private"}, True),
    ("mcp__remote__request", {"query": "Python documentation"}, False),
    ("mcp__siftfetch__fetch_url", {"url": "https://docs.example/"}, False),
    # exec code-mode JavaScript is deliberately not parsed as shell or MCP input.
    ("exec", {"code": "await tools.siftfetch__fetch_url({url:'https://docs.example/'})"}, False),
])
def test_codex_0163_payloads(invoke, monkeypatch, capsys, tmp_path, tool, args, denied):
    payload = {"session_id": "synthetic-session", "turn_id": "synthetic-turn", "model": "test-model",
               "tool_use_id": "call-test", "transcript_path": None, "permission_mode": "default",
               "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": args, "cwd": str(tmp_path)}
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
    assert hook.main() == 0
    output = capsys.readouterr().out
    if denied:
        assert json.loads(output)["hookSpecificOutput"]["permissionDecision"] == "deny"
    else:
        assert output == ""
