---
topic: claude-hook
status: verified
last-updated: 2026-10-28
---

# Claude hook
Review dry run before --apply. Close Claude Code before --apply: it rewrites ~/.claude.json while running. Keep both hooks and native deny rules. Never disclose identifiers to configure the guard.

```powershell
python -m siftfetch install --client claude --scope project
python -m siftfetch install --client claude --scope project --apply
python -m siftfetch doctor --client claude --scope project
```

User scope targets home .claude/settings.json and .claude.json; project scope targets .claude/settings.json and .mcp.json. Existing unrelated entries remain; changes are backed up.

Identical hook entries are a no-op. A differing entry running siftfetch.hook is refused unless install --replace is selected. Replacement recognizes hook/server module invocations structurally, retains matcher coverage and isolation flags, and replaces the interpreter. Unrecognized entries require owner reconciliation.

Immediately before atomic replacement, install re-reads the target bytes. A concurrent change aborts that file with "settings changed during install; close the client and retry", keeps its backup and exits 2. Earlier file changes may remain; installation is not transactional. User-scope dry runs print the close-client reminder.

| Entry | Purpose |
|---|---|
| PreToolUse matcher | WebFetch/WebSearch/Bash/PowerShell/Edit/Write/MultiEdit/NotebookEdit/apply_patch/MCP |
| command | Absolute Python, -I -m siftfetch.hook (-I keeps the working folder off the import path) |
| onFailure=block | Claude Code 2.1.295+ blocks startup failures/crashes/timeouts |
| PostToolUse | Label Chrome page responses |
| permissions.deny | Policy-folder Read/Edit, local/global dotenv Read patterns |

Restart and perform owner live checks. Regenerate deny paths when policy moves. Standard and optional Lockdown both deny native WebFetch/WebSearch and include PreToolUse plus Chrome PostToolUse labeling. Lockdown also enables guard_lock. Registration remains configured; verification pending. [Hook limits](../hook.md) apply; shell inspection is static.
