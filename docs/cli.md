---
topic: cli
status: verified
last-updated: 2026-10-29
---

# Command line
Setup, configure and tighten never loosen policy. Identity entry belongs in the owner's editor. Owner-run uninstall restores owned client settings after interactive confirmation; the hook denies agent uninstall --apply. This is a speed bump, not authentication. Only `get` uses the network; no command calls models. Use `siftfetch` or `python -m siftfetch`.

| Command | Effect |
|---|---|
| get URL [-o FILE] [-Lsf] [-H HEADER] [-A UA] | Checked web fetch; see [shell fetch](shell-fetch.md) for JSON, PDF, sidecars and quarantine |
| init | Create absent packaged JSON examples; empty identifiers; never overwrite either format |
| setup | Five-prompt wizard: clients, scope, preset, editor, confirmation |
| setup --preset standard/lockdown/custom --client claude/codex --scope user/project [--apply] | Noninteractive plan; repeat --client for both; applies only tightening/additive changes |
| configure [--setting ITEM] [--loosen] [--open-editor] | Redacted policy status and loosening costs; tighten named setting or hand off |
| tighten enabled/guard-lock/secret-files/browser-off | Apply allowlisted tightening |
| tighten blocked-domain HOST | Add one validated blocked domain; never prints it |
| install --client claude/codex [--scope user/project] [--replace/--adopt] [--apply] | Compatible installer; dry run by default; default user scope |
| uninstall [--client claude/codex] [--scope user/project] [--apply] | Preview receipt-owned reversions/conflicts; default both clients/user scope; apply requires typing uninstall; no --yes flag |
| doctor/status [--client claude/codex] [--scope user/project] [--json] | Read-only checks; default both clients/user |
| python -m siftfetch.sightings [--since 7d] [--by domain/category] [--json] | Offline detection review |
| python -I -m siftfetch.hook [--deny] | JSON stdin hook |
| python -I -m siftfetch.server | Stdio MCP server |

## Presets and wizard
The wizard detects clients without launching them. Use a stable pipx/uv interpreter. Apply initializes only absent policy stems. Close Claude Code before apply: it rewrites .claude.json.

| Setting | Standard (default) | Lockdown (optional) | Custom |
|---|---|---|---|
| PreToolUse hook | Full matcher coverage | Same | Same |
| MCP server | Added | Same | Same |
| Claude deny rules | Policy Read/Edit; local/global dotenv Read; WebFetch/WebSearch | Same | Same |
| Codex web_search | disabled | disabled | disabled |
| Codex shell_environment_policy.ignore_default_excludes | false | false | false |
| guard_lock | Off on fresh init; retain existing | On; add install package and interpreter environment paths | Keep or enable/add paths |
| secret_file_mode | Keep existing; fresh init strict | strict | Keep or tighten to strict |
| browser_fetch.mode | Keep existing; fresh init off | off | Keep or tighten to off |
| Claude Chrome PostToolUse labeling | Add | Same | Same |
| enabled, identities and other keys | Retain existing; fresh init defaults | Same | Same |

Standard routes web content through SiftFetch and disables built-in web tools. Lockdown also guards settings edits, within static hook limits. `strict` is a deprecated alias for `lockdown`.

Custom starts from Standard: `custom guard-lock,paths,secret-files,browser-off`. Omitted items remain unchanged; included items tighten. Chrome labeling is always included. Loosening uses the owner editor. Restart clients, re-trust the hook in Codex `/hooks`, then run doctor.

## Configure and writes
ITEM is enabled, guard-lock, secret-files, browser-off, blocked-domain, contact-alias or substitute. Identity changes always use the editor, including first assignment. Loosen prints only the path, key and replacement text. EDITOR selects the detached editor; otherwise notepad on Windows, open on macOS or xdg-open elsewhere. No value arguments/stdin.

Tightening validates effective JSON/TOML state and environment effects. Unknown/malformed baselines, unclassified changes and mixed plans refuse entirely before mutation. Config writes validate with validate_policy, back up, preserve format/comments, and atomically replace files. Unsupported TOML layouts require owner editing. Identifiers/exceptions remain create-only through init.

## Install and receipt
Targets: Claude user .claude/settings.json plus .claude.json; Claude project .claude/settings.json plus .mcp.json; Codex .codex/config.toml plus .codex/hooks.json. Existing unrelated entries remain. Install includes Chrome labeling. `--replace` recognizes commands running siftfetch.hook/server structurally and preserves existing matcher coverage; without it, differing entries refuse.

Changed files get unique .siftfetch-backup-UUID backups. Links/junctions refuse. Codex TOML retains comments/layout; unsafe forms refuse. Snapshot drift aborts replacement with exit 2. Replacement is atomic per file.

The policy-folder install-manifest.json records ownership, hashes and prior managed scalars/absence. Pre-existing entries stay unowned unless adopted. Intent precedes writes. Uninstall preserves user changes, reports conflicts, restores prior scalars/absence and removes hooks last. Interrupted journals are never replayed. Policy/data files stay untouched. A second prompt offers deletion of manifest-listed backups (which may contain client tokens), defaulting to keep. No whole-file restoration occurs.

Without a receipt, uninstall recognizes SiftFetch hooks/servers; uncertain denies/scalars remain.

`install --adopt` previews hand-wired module commands (optional -I, hook --deny) or siftfetch-hook/server executables. Add --apply for backups and ownership. Matchers/events retain coverage; unknown arguments/options or mixed handlers refuse. Only exact canonical denies become owned; others remain and are reported. Run doctor; uninstall removes adopted registrations.

## Doctor and exits
Doctor retains policy_status and checks (status, check, detail). It checks package imports, policy sanity, directories, hook coverage/interpreters, MCP, native web denial and environment filtering, plus journal state. Reports remain **configured; verification pending**. Files cannot prove trust/restart. INFO names [gaps by design](threat-model.md). See [live checks](setup/troubleshooting.md).

| Exit | Meaning |
|---|---|
| 0 | Completed/dry run/cancelled; doctor structural checks passed; live verification still pending |
| 1 | Doctor/status found a failed check |
| 2 | Invalid usage, refused transition, conflict/malformed state, unsafe path or I/O failure |
