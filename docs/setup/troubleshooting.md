---
topic: troubleshooting
status: verified
last-updated: 2026-10-28
---

# Troubleshooting
First, ask your agent to run `python -m siftfetch doctor` or call `policy_status`; it shows the shape, never values.

Never fix a block by rerouting a protected value or weakening permissions. Doctor reports structure/counts without values.

| Symptom | Action |
|---|---|
| policy_unavailable | Owner repairs missing/malformed/conflicting policy or unsafe substitutes |
| blocked_domain | Choose another source |
| guard_lock_unknown | Restore valid required policy; built-ins stay locked |
| Hook never fires | Check interpreter, registration, restart and trust |
| No API contact | Owner configures an approved email; reserved domains are ignored |
| secret_file | Read a template for key names |
| Browser unavailable | Check optional dependency, mode and rate cap |
| Unsafe download directory | Choose local writable directory without links |
| Install server conflict | Owner reconciles existing entry; installer preserves it |
| Hand-wired SiftFetch without receipt | Preview install --client claude/codex --adopt; inspect, then --apply. Known module/executable commands retain coverage, move to the current interpreter with -I and become owned; no duplicate standard entry is added where adopted ones cover the required tools. timeout/statusMessage are replaced; Codex hooks.state stays; TOML [[hooks.*]] arrays are edited in place. Unknown options, a non-empty server env or other shapes refuse. Run doctor; uninstall removes adopted entries. Noncanonical denies remain. |
| Different interpreter | Preview install --replace; only structurally recognized SiftFetch entries can change; restart and re-trust afterward |
| Temporary interpreter | Install with pipx or uv tool install into a stable environment |
| Pending install journal | Stop automatic retries; inspect receipt/backups locally; doctor/uninstall never replay interrupted intent |
| Uninstall conflict | Entry changed since installation or is ambiguous; keep it and reconcile locally |
| Tightening refused | Repair malformed/unknown state or use configure --loosen for editor guidance; no TTY bypass exists |
| Test temp/cache inaccessible | Choose fresh repository-local basetemp/cache paths |

## Owner live checks
Run deliberately after installation/restart/hook changes/client updates, using synthetic canaries in temporary policy. Automated tests never launch agents/models.

1. Fetch example.com through SiftFetch; expect an envelope.
2. Enter a synthetic protected canary locally; verify URL/query/header and shell blocks.
3. Retrieve an approved substitute and verify it is usable.
4. Disable egress; expect the disabled notice and one hook log line per call, with secret-file blocks intact. Restore enabled.
5. Block example.com; check subdomains and redirects into it.
6. Verify Claude deny rules/startup failure and Codex trusted Bash/apply_patch/MCP events. Inspect the known code-mode gap.
7. Check download root, quarantine sidecars, sightings rotation and doctor output.

Publication and live client trust checks remain owner actions. Source extraction is unsupported; use implemented extraction levels or a deliberate labeled raw-body library workflow.

Status remains configured; verification pending until owner live checks. Doctor cannot verify Codex trust. Review [known gaps and research](../threat-model.md). EDITOR selects the detached editor; fallback is notepad on Windows, open on macOS, xdg-open elsewhere. SiftFetch never prints editor file contents.
