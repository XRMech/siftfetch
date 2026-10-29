---
topic: codex-hook
status: verified
last-updated: 2026-10-28
---

# Codex hook
Trust the exact hook in /hooks. Registration is not proof of enforcement. Native Claude Read deny rules have no equivalent in this installer; owner must verify sandbox read restrictions.

```powershell
python -m siftfetch install --client codex --scope project
python -m siftfetch install --client codex --scope project --apply
python -m siftfetch doctor --client codex --scope project
```

| Setting | Installed behavior |
|---|---|
| hooks.PreToolUse | In hooks.json: `"<python>" "-I" "-m" "siftfetch.hook" "--deny"`; every argument quoted for Codex's parser |
| web_search | disabled; hosted search bypasses local checks |
| shell_environment_policy.ignore_default_excludes | false; retain environment filtering |
| mcp_servers.siftfetch | Python stdio server |

Scope chooses home/project .codex/config.toml and .codex/hooks.json. Install defaults to dry run. Hooks merge as JSON; identical entries are a no-op. A different command running siftfetch.hook is refused with "existing siftfetch hook differs; owner must reconcile it manually", including legacy TOML entries. Doctor accepts hooks.json or [hooks] in config.toml; Codex merges both sources.

TOML edits preserve unrelated bytes, comments and layout. Install changes only the top-level web_search value (or inserts it before the first table), appends an absent MCP table and sets/inserts the environment key in its table. Equal existing servers remain unchanged; differing servers and unsafe dotted-key/inline-table forms require owner reconciliation. The result must parse to the intended merge before writing. Backups precede atomic replacements; concurrent changes abort replacement and retain backups.

## Payload and live limits
Bash/apply_patch carry tool_input.command. Patch source/delete/move paths are checked. turn_id forces deny instead of ask. Tests cover Codex 0.163 payloads; live trust/startup-failure checks remain owner-run after updates.

Code-mode exec JavaScript is not parsed. Protection needs canonical Bash/apply_patch/MCP events. write_stdin, children and hosted tools have incomplete visibility. Do not weaken guards to make setup pass.

Use install --replace to change a structurally recognized SiftFetch interpreter registration, including legacy TOML hooks. Existing matcher coverage and isolation flags are retained. Restart clients, re-trust the exact hook in `/hooks`, then run doctor. Status remains configured; verification pending. See the [threat model](../threat-model.md) for Codex fail-open errors/timeouts.
