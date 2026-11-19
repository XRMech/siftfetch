---
topic: mcp-isolation-probe
status: verified
last-updated: 2026-11-18
---

# Test how an MCP host isolates conversations

The [stdio probe](../tools/mcp_isolation_probe.py) holds one random handle for one synthetic string per Python process. It offers no page, filesystem, shell or network tools. It takes no URL, file path or conversation name. The production server registers its own separate tools. The probe deliberately accepts its synthetic handle from anyone reaching that process. A successful cross-conversation read exposes a shared boundary.

## Run the offline controls

From a checkout with the test dependencies installed, run:

```powershell
.venv/Scripts/python.exe -m pytest -q tests/test_mcp_isolation_probe.py
```

The [SDK tests](../tests/test_mcp_isolation_probe.py) launch only the Python probe. They send real MCP messages over stdio with automatic protocol selection and with a forced legacy handshake. Two logical callers on the same initialized connection can read the same capture. Independent subprocesses reject the other process's handle for read, size and release. The tests check the owning process still serves its capture, then check explicit release, orderly pipe closure and rejection after worker restart.

## Prepare a host run

Use a disposable test project and a separate test registration. In the host's ordinary [stdio registration](setup/mcp-server.md), use `siftfetch-isolation-probe` as the server name. Set `command` to the absolute path of the checkout's virtual-environment Python interpreter. Set `args` to the two strings `-I` and the absolute path of `tools/mcp_isolation_probe.py`. Start the host with its normal trust and sandbox settings. Give it synthetic tool calls only. The complete tool list is:

| Tool | Inputs | Observation |
|---|---|---|
| `probe_instance` | None | Random instance marker, installed MCP SDK version and wire protocol version |
| `probe_open` | None | New synthetic handle and edition. Replaces this instance's prior capture. |
| `probe_access` | `ticket` from open, `operation` of `read`, `size` or `release` | Instance plus status. A valid read returns synthetic text; size reports UTF-8 bytes; release invalidates the handle. |

Process startup and orderly shutdown write `isolation-probe started INSTANCE` and `isolation-probe stopped INSTANCE` to stderr. Tool stdout remains MCP protocol data. During these checks the handle stays active on its process until explicitly released, replaced or disconnected.

## Run the same sequence for each host mode

1. In A, call `probe_instance` and `probe_open`. Save its instance, handle and edition. Read twice and size once with that handle. The instance, text and byte count must agree.
2. While A remains open, call only `probe_instance` in B. Give B the exact synthetic handle from A. In B try read, size and release, in that order. Record B's instance and all three statuses. A must still be able to read its original edition if the boundary held.
3. Close A while its capture is live. Record the matching stop in host stderr or confirm process exit using the host's own lifecycle diagnostics. Start a fresh conversation, pass it A's old handle, and repeat read, size and release. An absent stop after a forced termination needs independent evidence of process exit.
4. Exercise each row below with fresh captures. Record host and launcher version, host registration scope, mode, SDK and protocol, instance markers, foreign-operation statuses, owner re-read result and teardown evidence. Record unsupported modes explicitly.

| Scenario | A and B |
|---|---|
| Concurrent | Two independent conversations in the same project |
| Sequential | Close A, then create a new conversation in the same host |
| Delegated | Parent and separately running child |
| Forked | Original and fork that inherited its transcript and handle |
| Resumed | Before and after resume, plus an independent sibling conversation |
| Disconnected | Original worker and new occupant after disconnect or host restart |

Apply the matrix separately to Claude Code user registration, Claude Code project registration and Codex registration, in interactive and unattended modes used by the deployment. For resume, record whether the owner retains or loses its capture; a fresh context may legitimately lose it.

In a headless Claude Code 2.1.327 check, independent CLI launches received distinct probe instances. A parent and its built-in general-purpose subagent reached the same instance. Process lifetime alone therefore cannot enforce separate capture ownership for this deployment. The standard stdio reading tools create and close a flow inside each call. A host that controls dispatch can give each conversation its own [private MCP connection](host-flow.md).

A shared instance across independent flows rules out using that process lifetime for isolation. Any successful foreign read, size or release is a failure. Unexpected owner failures, unreachable tools and missing lifecycle evidence are inconclusive. Distinct instances, consistent same-flow access, foreign rejection and confirmed teardown establish observations for the tested configuration. Recheck when the host, launch mode, transport or SDK changes. Production cross-call reuse additionally needs a host-owned flow binding and cleanup verification.
