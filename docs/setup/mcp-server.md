---
topic: mcp-server
status: verified
last-updated: 2026-10-27
---

# MCP server
Use the Python interpreter with SiftFetch installed. Stdout belongs to MCP. Never put protected identifiers or credentials into registration data.

```powershell
python -I -m siftfetch.server
```

The [installer](../cli.md) merges entries. Manual examples use PY for an absolute interpreter:

```json
{"mcpServers":{"siftfetch":{"command":"PY","args":["-I","-m","siftfetch.server"]}}}
```

```toml
[mcp_servers.siftfetch]
command = "PY"
args = ["-I", "-m", "siftfetch.server"]
```

| Option | Guidance |
|---|---|
| SIFTFETCH_HOME | Owner-configured policy |
| SIFTFETCH_DATA | Artifact/log root |
| SIFTFETCH_DOWNLOAD_DIR | Independent download root |
| SIFTFETCH_ATTENDED=1 | Owner opt-in for interactive login use |
| AGENT_HEADLESS=1 | Force unattended |

Claude user MCP entries use .claude.json, project entries .mcp.json; Codex uses .codex/config.toml. Restart after registering. See [tools](../mcp-tools.md) and [SDK-free library](../library-api.md).
