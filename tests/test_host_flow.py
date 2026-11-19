import json

import anyio
import pytest

from siftfetch import host_flow, research_flow
from test_research_flow import public_page


async def call(client, name, **args):
    result = await client.call_tool(name, args)
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)


def test_private_connections_isolate_simultaneously_live_conversations(public_page):
    origin, seen = public_page

    async def scenario():
        async with host_flow.open_host_flow() as parent:
            first = await call(parent, "open_page", url=origin + "/article")
            async with host_flow.open_host_flow() as child:
                second = await call(child, "open_page", url=origin + "/article")
                assert first["handle"] != second["handle"]
                for client, foreign in ((parent, second), (child, first)):
                    for tool in ("read_page", "page_sizes"):
                        result = await call(client, tool, handle=foreign["handle"])
                        assert result["status"] == "unavailable"
                    await call(client, "release_page", handle=foreign["handle"])
                child_read = await call(child, "read_page", handle=second["handle"])
                assert "Edition 2" in child_read["content"]
            parent_read = await call(parent, "read_page", handle=first["handle"])
            assert "Edition 1" in parent_read["content"]
            assert len(research_flow._captures) == 1
        assert not research_flow._captures
        async with host_flow.open_host_flow() as fresh:
            result = await call(fresh, "read_page", handle=first["handle"])
            assert result["status"] == "unavailable"

    anyio.run(scenario)
    assert seen == ["/article", "/article"]


def test_host_exception_releases_capture(public_page):
    origin, _ = public_page

    async def scenario():
        with pytest.raises(ExceptionGroup) as caught:
            async with host_flow.open_host_flow() as client:
                await call(client, "open_page", url=origin)
                raise ValueError("synthetic host error")
        assert caught.value.subgroup(ValueError)
        assert not research_flow._captures

    anyio.run(scenario)


def test_cancelling_one_host_task_preserves_another(public_page):
    origin, _ = public_page

    async def scenario():
        ready = anyio.Event()

        async def worker():
            async with host_flow.open_host_flow() as client:
                await call(client, "open_page", url=origin)
                ready.set()
                await anyio.sleep_forever()

        async with host_flow.open_host_flow() as owner:
            captured = await call(owner, "open_page", url=origin)
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(worker)
                await ready.wait()
                assert len(research_flow._captures) == 2
                tasks.cancel_scope.cancel()
            assert len(research_flow._captures) == 1
            read = await call(owner, "read_page", handle=captured["handle"])
            assert "Edition 1" in read["content"]
        assert not research_flow._captures

    anyio.run(scenario)
