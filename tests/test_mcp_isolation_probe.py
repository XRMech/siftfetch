"""Exercise a multiplexed host and independent processes using real stdio SDK clients."""
from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys

import anyio
from mcp import Client, StdioServerParameters, stdio_client
import pytest


PROBE = Path(__file__).resolve().parents[1] / "tools" / "mcp_isolation_probe.py"


@asynccontextmanager
async def connect(log, mode):
    params = StdioServerParameters(command=sys.executable, args=["-I", str(PROBE)])
    with log.open("w", encoding="utf-8") as errlog:
        async with Client(stdio_client(params, errlog=errlog), mode=mode, read_timeout_seconds=10) as client:
            yield client


async def call(client, tool, **arguments):
    result = await client.call_tool(tool, arguments)
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_probe_classifies_shared_separate_and_restarted_hosts(tmp_path, mode):
    async def scenario():
        first_log = tmp_path / "a.log"
        async with connect(first_log, mode) as first:
            info = await call(first, "probe_instance")
            assert info["protocol"] == first.protocol_version
            original = await call(first, "probe_open")
            assert original["instance"] == info["instance"]
            token = original["handle"]

            # Two logical callers are routed through one host-owned SDK connection.
            # Successful access here is the control that identifies a shared boundary.
            first_read = await call(first, "probe_access", ticket=token, operation="read")
            second_read = await call(first, "probe_access", ticket=token, operation="read")
            assert first_read == second_read
            assert second_read["content"] == f"Synthetic capture {original['edition']}"
            size = await call(first, "probe_access", ticket=token, operation="size")
            assert size["size_bytes"] == len(first_read["content"].encode("utf-8"))

            async with connect(tmp_path / "b.log", mode) as independent:
                other = await call(independent, "probe_open")
                assert other["instance"] != original["instance"]
                for operation in ("read", "size", "release"):
                    observation = await call(independent, "probe_access", ticket=token, operation=operation)
                    assert observation == {"instance": other["instance"], "status": "unavailable"}
                assert (await call(first, "probe_access", ticket=token, operation="read")) == first_read
                release = await call(first, "probe_access", ticket=token, operation="release")
                assert release["status"] == "released"
                assert (await call(first, "probe_access", ticket=token, operation="read"))["status"] == "unavailable"
            assert f"isolation-probe stopped {other['instance']}" in (tmp_path / "b.log").read_text()
            # Deliberately leave a live synthetic capture when the owning pipe disconnects.
            outstanding = await call(first, "probe_open")

        events = first_log.read_text()
        assert f"isolation-probe started {info['instance']}" in events
        assert f"isolation-probe stopped {info['instance']}" in events
        async with connect(tmp_path / "restarted.log", mode) as restarted:
            observed = await call(restarted, "probe_access", ticket=outstanding["handle"], operation="read")
            assert observed["instance"] != info["instance"] and observed["status"] == "unavailable"

    anyio.run(scenario)
