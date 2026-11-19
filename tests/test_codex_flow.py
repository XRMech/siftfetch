import json

import anyio

from siftfetch.codex_flow import open_codex_flow
from test_research_flow import public_page


def test_codex_flow_routing_and_close(public_page):
    url, seen = public_page

    def request(thread, name, **args):
        return {"threadId": thread, "turnId": "turn", "callId": "call", "namespace": "siftfetch",
                "tool": name, "arguments": args}

    async def scenario():
        async with open_codex_flow() as flow:
            specs = flow.dynamic_tools[0]["tools"]
            assert "open_page" in {s["name"] for s in specs}
            owner = request("owner", "open_page", url=url)
            assert not (await flow.dispatch(owner))["success"]
            flow.bind({"thread": {"id": "owner"}})
            result = await flow.dispatch(owner)
            assert result["success"]
            page = json.loads(result["contentItems"][0]["text"])
            assert page["handle"] and "UNTRUSTED WEB CONTENT" in page["content"]
            read = request("owner", "read_page", handle=page["handle"], view="full")
            for changed in ({"threadId": "child"}, {"namespace": None}, {"turnId": ""},
                            {"tool": "unknown"}, {"arguments": {**read["arguments"], "threadId": "owner"}}):
                assert not (await flow.dispatch({**read, **changed}))["success"]
            assert not flow.thread_closed({"threadId": "child"})
            assert (await flow.dispatch(read))["success"]
            assert flow.thread_closed({"threadId": "owner"})
            assert not (await flow.dispatch(read))["success"]
        assert not (await flow.dispatch(read))["success"]
    anyio.run(scenario)
    assert len(seen) == 1


def test_closure_during_mcp_call_suppresses_result():
    from types import SimpleNamespace
    from siftfetch.codex_flow import CodexFlow

    async def scenario():
        started, finish = anyio.Event(), anyio.Event()
        class SlowClient:
            async def call_tool(self, name, args):
                started.set()
                await finish.wait()
                return SimpleNamespace(is_error=False, content=[SimpleNamespace(type="text", text="late handle")])
        flow = CodexFlow(SlowClient(), [{"name": "read_page", "inputSchema": {"properties": {}}}])
        flow.bind({"thread": {"id": "closed"}})
        results = []
        async def work():
            results.append(await flow.dispatch({"threadId": "closed", "namespace": "siftfetch",
                                                "tool": "read_page", "turnId": "turn",
                                                "callId": "call", "arguments": {}}))
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(work)
            await started.wait()
            assert flow.thread_closed({"threadId": "closed"})
            finish.set()
        assert not results[0]["success"] and "late handle" not in str(results)
    anyio.run(scenario)
