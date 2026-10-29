---
topic: hook
status: verified
last-updated: 2026-10-29
---

# Hook contract and limits
The hook inspects call text, not runtime behavior. It is not a sandbox: generated commands, child processes, stdin continuation and hosted tools can bypass its view. Keep native file deny rules and use SiftFetch transport for pinned checks.

## Payload and output
Both clients send JSON stdin; UTF-8 BOM is accepted. Claude uses tool_name, tool_input, hook_event_name and optional cwd/agent_id. Codex Bash/apply_patch use tool_input.command and optional turn_id. MCP input is its argument object. Patch Add/Update/Delete/Move paths are checked.

```json
{"tool_name":"WebFetch","tool_input":{"url":"https://example.com"},"hook_event_name":"PreToolUse"}
```

Ordinary allow exits 0 silently. [Shell fetch reroutes](shell-fetch.md) return allow with updatedInput (whole input object, string command) and additionalContext after existing denials pass. Deny/ask exits 0 with:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Blocked by privacy policy (blocked_domain)."}}
```

--deny, headless, subagents and Codex turn IDs convert asks to deny. Chrome PostToolUse adds labeled additionalContext; it cannot remove the original response. Malformed input denies; import failure denies matched tools.

Inbound labeling uses the shared reader-instruction, multilingual and bounded decoding scanner. Inactive code examples stay below medium unless nearby prose adopts them. Attribute inventories are produced by HTML cleaning on fetch routes; the Chrome hook can scan only the text supplied by its client. See [MCP output](mcp-tools.md) for attribute labels and limits.

## Reason codes
Codes are data, never permission to reroute protected values. Logs hold labels/reasons and hashed sensitive hosts, never request values.

| Code | Meaning/action |
|---|---|
| ok | Allowed |
| disabled | Value checks disabled; one hook line per call, even when file checks deny |
| blocked_domain | Owner blocks destination; use another source |
| protected_value | Exact identifier; use substitute of blocked kind or omit |
| protected_value_no_alias | Guidance variant: no email alias |
| soft_identifier | Restricted contextual identifier; omit/ask owner |
| credential | Recognized credential; omit |
| policy_unavailable | Missing/malformed/conflicting policy; owner repairs |
| ambiguous_request | Cannot safely interpret URL; canonicalize without protected data |
| could_not_check | Decode budget exhausted |
| oversized_input | Input exceeds 1 MB budget |
| private_destination | Unlisted private/loopback/link-local host |
| destination_unconfirmed | DNS failed/missing/timed out |
| secret_file | Recognized dotenv read; use a template |
| policy_protected | Policy-folder access/change |
| guard_lock | Modification of locked settings |
| guard_lock_unknown | Invalid/missing lock policy; built-ins stay locked |
| management_command | Recognized management invocation is not an allowed diagnostic, dry run or tightening |
| malformed_input | Invalid hook/patch payload |
| guard_error | Hook failed internally (exception type named); fails closed, report it |
| recursive_walk_limit | 20000 names reached; allowed and logged |
| network_error | Library/MCP failure, not hook permission |
| bad_request, unsupported, type_mismatch | Download option/type failure |
| unsafe_staging, too_large, timeout | Download path/budget failure |

## Coverage and blind spots
Deny rules and the hook stop tool calls and commands that name the policy folder. A program the agent starts runs as your account and can still read it. OS-level separation (a different account or ACL) is the only full boundary.
Value checks cover WebFetch/WebSearch, all Bash/PowerShell commands and non-exempt MCP string leaves. Network commands also check soft values. Literal URLs/common network-host operands receive domain checks; generated hosts/arbitrary shell syntax remain outside coverage. SiftFetch MCP tools enforce internally. Local MCP exemptions skip value checks, not literal domain blocks.

Codex code-mode exec JavaScript is not interpreted. Coverage needs a canonical Bash/apply_patch/MCP event. write_stdin is not a new PreToolUse event. Trust hooks in /hooks; startup-failure behavior requires owner live verification.

WebFetch DNS is best-effort with one-second deadline; the native tool resolves again. SiftFetch fetch/download pins each redirect. Browser proxy checks every connection host, but Playwright does not expose HTTPS redirect paths. DDGS engine connections are outside pinned transport.

Secret-file checks remain while disabled. Strict mode recognizes print/redirect/source/copy/interpreter and supported recursive reads. Standard covers print/redirect; off disables shell dotenv checks. File-tool deny rules remain separate. Recursive inspection stops at depth three and skips build/vendor folders. Runtime paths may evade it. Guard lock protects settings/hooks/Codex/project-MCP config, not OS immutability.

Built-in lock paths include .codex/hooks.json and home .claude.json. The management guard recognizes siftfetch, python/py -m siftfetch and nested shells to depth three. get, doctor/status, install/setup/uninstall dry runs, --help and CLI tighten are allowed; configure, apply flags and unknown combinations deny. Literal echo and quoted cat/tee heredoc prose are not invocations. See the [threat model](threat-model.md).
