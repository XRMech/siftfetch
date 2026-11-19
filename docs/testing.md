---
topic: testing
status: verified
last-updated: 2026-10-27
---

# Testing
Automated tests never spawn claude/codex/gemini binaries, import model SDKs, call models or spend tokens, including skipped/opt-in tests. They never leave the machine: only loopback (127.0.0.1, ::1, localhost) test servers are allowed. Use loopback servers or mocked transports and temporary synthetic policies. Never access real policy, dotenv or secret folders.

## Offline suite
Install test dependencies, then run:

```powershell
.venv/Scripts/python.exe -m pytest -q
```

Conftest isolates policy/data and clears alias/switch/download overrides. It denies DNS, connect and bind to any non-loopback address. Loopback servers in the suite cover redirects, cookies, pinning, size/time budgets and the egress proxy. Windows asyncio's stdlib socketpair wakeup pipe is also allowed (process-local signaling). Browser unit tests mock Playwright and proxy. Hook subprocesses launch Python only and use a fake resolver.

The no-token AST guard scans all test modules, including skipped code, for SDK imports and agent launches, resolving assigned command strings and aliases. It is a regression gate, not proof against deliberately obfuscated Python. Review dynamic imports/process construction manually.

## Real-browser probe
`tests/test_browser_fetch_live.py` launches a real off-screen browser against loopback pages, so it is skipped unless the optional browser dependency is installed and SIFTFETCH_BROWSER_TESTS=1 is set. It never calls models or agents.

```powershell
$env:SIFTFETCH_BROWSER_TESTS = "1"; .venv/Scripts/python.exe -m pytest -q tests/test_browser_fetch_live.py
```

Client/model live checks belong to a separately scheduled owner harness, never this suite.

## Navigation and MCP isolation acceptance

Run `tests/test_live_navigation.py`, `tests/test_pagination.py` and `tests/test_mcp_isolation_probe.py` for the public navigation and MCP isolation checks. With Playwright and a supported local browser installed, `SIFTFETCH_BROWSER_TESTS=1` includes the real Chromium viewport test against synthetic content and a loopback receiver. Use the [host matrix](mcp-isolation-probe.md) in disposable client projects to verify actual conversation, delegation and restart boundaries.

The registered image and navigation tool checks are in `tests/test_mcp_images.py` and `tests/test_mcp_navigation.py`. They exercise inventory selection, page changes, per-request outbound checks and marked evidence. With Playwright and a local browser available, enable `SIFTFETCH_BROWSER_TESTS=1` for the registered viewport check.

## Research archive checks

Run the site cases, report candidate and case trends tests for local retention, privacy screening, snapshot provenance, review labels and repeat observations. These tests use synthetic policies and temporary storage. See [research cases](research-cases.md).

## Docs checks
The docs lint checks frontmatter, verified absolute dates, budgets, tagged fences, relative links and coverage of public functions, MCP tools, config/environment keys and reason codes. Package tests keep init resources aligned with repository examples. See [writing rules](writing-docs.md).
