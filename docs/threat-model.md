---
topic: threat-model
status: verified
last-updated: 2026-10-29
---

# Threat model
SiftFetch cleans and labels web content, then checks outbound values. Optional Lockdown guards settings. Outside content never authorizes changes to the owner's task.

## Primary: poisoned data in
Hidden text is removed or marked. Scanning combines known patterns with reader-directed signals: addressee, conversation references, obligation, concealment, data movement and authority. Windows span up to three blocks/900 characters, excluding headings and code. Spotlighting, envelopes and sightings label provenance and risk; they cannot force safe model behavior.

Hard-wrapped prose splits at sentence-ending lines/page markers with a 900-character cap; short instruction continuations still join. Optional PDF extraction scans text, not images or OCR. Missing extraction is reported plainly.

Attribute labels expose accessibility text, metadata, SVG and JSON fields (32,768 characters); presence alone does not raise risk. Decoding caps: 128 attempts, 8,192 characters/run, 32,768 bytes, two layers; data URIs excluded. Multilingual, mixed-script, tool-shaped, reference-image and URL-template instructions are checked. Inactive code examples stay below medium.

Standard denies Claude WebFetch/WebSearch and disables Codex web_search because they bypass cleaning. Chrome PostToolUse labels supported outputs without the full fetch pipeline. Hook/transport coverage limits routing.

Default shell_fetch reroutes literal public fetches through `get`; unsafe/compound forms deny. Local hosts retain existing guards. Scripts, alternate clients and generated commands can bypass [shell routing](shell-fetch.md).

Novel semantics, unsupported languages, image/OCR text, distant or cross-fetch composition, budget overflows and misleading claims can escape detection. Bare contact URLs are insufficient evidence of exfiltration. Grades are heuristics. Outbound checks separately protect supported routes.

## Secondary (optional): agents going rogue
Lockdown enables guard_lock with install paths, strict secret-file checks and browser fetch off. SiftFetch does not contain a determined agent running as the user. Registration means **configured; verification pending**. Restart clients, re-trust the exact Codex hook in `/hooks`, then run doctor and owner live checks.

### What holds within the supported routes
Controls depend on valid policy and clients invoking trusted hooks.

| Control | What it does | Boundary |
|---|---|---|
| Hook denials | Reject visible unsafe tool calls and recognized management commands | Static call text; requires client enforcement |
| Deny rules | Block native policy-folder and dotenv reads, and Claude web tools | Client-specific rules; Codex has no equivalent Read rule here |
| Guard lock | Reject visible edits, redirects, deletion and rename of protected settings | Includes .codex/hooks.json and .claude.json; not OS immutability |
| Value checks | Match identifiers and credentials in supported outbound inputs | SiftFetch transport and supported hook routes only |
| Spotlighting | Mark outside prose provenance and suspicious instructions | Labels help interpretation; they cannot force model behavior |
| Domain blocklist | Deny validated destination patterns, including when value checks are off | Runtime-generated hosts outside observed routes may escape |
| Fail-closed policy | Refuse checked requests on malformed, conflicting or unknown security state | Does not force clients to honor a failed hook |

### What does not hold, and why
Programs launched by an agent run as the user. `python x.py` can edit files without exposing its contents to the hook, patch site-packages or install a `.pth` file. Lockdown's package/environment lock only adds static path coverage.

TTY emulation cannot authenticate an owner. Configure and tighten never loosen policy. Owner-run uninstall is the exception: typing `uninstall` permits owned restoration or conservative legacy removal. The hook denies `uninstall --apply`; neither guard nor prompt authenticates the owner. No `--yes` exists. Policy/data folders remain. Launch-time environment overrides can change policy location or disable value checks; the hook cannot control its parent.

Codex skips untrusted hooks and fails open on callback errors, malformed responses and timeouts. Re-trust after every hook change. Code-mode exec JavaScript is not interpreted as shell code. Hosted tools and child processes may never traverse the local hook or transport. Client trust and sandbox checks remain owner-run.

Backups may contain credentials. Never print or restore whole backups over later edits. After uninstall, a separate prompt offers deletion of manifest-listed backups; default keep. The hook, server and other same-user processes can read identifiers: write protection cannot provide read confidentiality.

## Needs further research and testing
Research topics, not guarantees.

| Topic | Required investigation |
|---|---|
| Novel semantics and languages | Rules plateau on free phrasing; local classifier deferred (memory) |
| Cross-fetch payloads | Evaluate composition beyond per-response scanning |
| Markdown and links | Test renderer ambiguity and opaque destinations |
| False positives | Measure flags on security documentation |
| Cleaning effectiveness | [Benchmark](benchmark.md): detection, false positives, containment; model resistance unproven |
| Hardened mode | Code outside the profile; Administrators-owned %ProgramData% policy; managed client hooks; narrow UAC helper validating exact operations |
| UAC boundary | Elevation is dependable only with Always notify, a standard account, or Administrator Protection; default admin auto-elevation paths can undermine the intended consent boundary |
| Profile rename/recreate | ACL-only locking must protect parent rename/deletion and recreation; a protected child alone is insufficient |
| Elevated-agent detection | Detect privileged agent tokens and refuse unsafe management without treating markers as authentication |
| Sandbox and network egress | Separate principals and enforced network destinations beyond static command inspection |
| Client enforcement gaps | Fail-open behavior, trust changes, alternate events, hosted tools and code-mode execution |
| Smarter agents | Test indirect commands and writers |
| Identifier confidentiality | Separate reader principal; same-user services cannot hide readable values |

See [hook](hook.md), [configuration](configuration.md) and [troubleshooting](setup/troubleshooting.md).
