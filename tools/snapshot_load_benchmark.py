"""Offline process-level load measurement for the Python ResearchFlow API."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import sys
from tempfile import TemporaryDirectory
import threading
import time
from unittest.mock import patch


PAGE_BYTES = {"small": 8 * 1024, "large": 1280 * 1024}


def _peak_rss_bytes():
    """Process lifetime high-water mark, including native parser allocations."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "peak_working_set", "working_set", "peak_paged_pool", "paged_pool",
                    "peak_nonpaged_pool", "nonpaged_pool", "pagefile", "peak_pagefile")
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
                ctypes.c_void_p(-1), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError()
        return counters.peak_working_set
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if sys.platform == "darwin" else peak * 1024
    return None


def _page(index, size):
    intro = (f"<!doctype html><html><body><main><h1>Survey station {index}</h1>"
             f"<p>Sample {index} measured 37 millimetres.</p><p>"
             + "Record the gauge reading after the water settles. " * 20
             + "</p></main><script>/* bundled resource ").encode()
    end = b" */</script></body></html>"
    return intro + b"0" * (size - len(intro) - len(end)) + end


def _measure(count, size):
    import httpx
    from siftfetch import research_flow
    from siftfetch.research_flow import ResearchFlow

    fetches = Counter()
    lock = threading.Lock()
    urls = [f"https://snapshot.example/station/{i}" for i in range(count)]
    start_gate = threading.Barrier(count)

    def synthetic_fetch(url, *, browser, session_kind):
        i = urls.index(url)
        if browser != "none" or session_kind != "unattended":
            raise AssertionError("Expected an anonymous fetch")
        with lock:
            fetches[i] += 1
        return httpx.Response(200, request=httpx.Request("GET", url), content=_page(i, size),
                              headers={"Cache-Control": "public", "Content-Type": "text/html"},
                              extensions={"siftfetch_public_direct": True})

    with ExitStack() as stack:
        flows = [stack.enter_context(ResearchFlow()) for _ in urls]
        stack.enter_context(patch.object(research_flow.tools, "fetch", synthetic_fetch))
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=count))

        def first(i):
            start_gate.wait(timeout=60)
            read = flows[i].fetch(urls[i])
            if not read.handle or f"Sample {i} measured 37 millimetres." not in read.content:
                raise AssertionError(f"Capture or first-read evidence missing for station {i}")
            return read.handle

        def followup(i):
            try:
                read = flows[i].read(handles[i], extract="full")
            except KeyError:
                return False
            if f"Sample {i} measured 37 millimetres." not in read.content:
                raise AssertionError(f"Wrong follow-up evidence for station {i}")
            return True

        initial_peak = _peak_rss_bytes()
        started = time.monotonic()
        handles = list(pool.map(first, range(count)))
        with research_flow._changed:
            retained = len(research_flow._captures)
            retained_bytes = sum(item.size for item in research_flow._captures.values())
        if retained_bytes > research_flow._MAX_TOTAL or retained > research_flow._MAX_ENTRIES:
            raise AssertionError("Capture retention exceeded the configured limits")
        successful = sum(pool.map(followup, range(count)))
        if successful == 0 or fetches != Counter(range(count)):
            raise AssertionError("Expected capture reuse and exactly one fetch per station")
    with research_flow._changed:
        if research_flow._captures:
            raise AssertionError("A capture survived flow close")
    return {"platform": platform.system(), "python": platform.python_version(),
            "flows": count, "html_bytes_per_flow": size, "fetch_calls": sum(fetches.values()),
            "retained_after_first_reads": retained, "retained_payload_bytes": retained_bytes,
            "successful_followups": successful, "unavailable_followups": count - successful,
            "retained_after_close": 0, "initial_peak_rss_bytes": initial_peak,
            "peak_rss_bytes": _peak_rss_bytes(), "elapsed_seconds": round(time.monotonic() - started, 2)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", type=int, choices=(20, 30), default=30)
    parser.add_argument("--page", choices=PAGE_BYTES, default="small")
    args = parser.parse_args()

    def deny_network(event, _args):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.bind", "socket.sendto"}:
            raise RuntimeError("Network access is unavailable in the offline load benchmark")

    sys.addaudithook(deny_network)
    with TemporaryDirectory() as directory:
        root = Path(directory)
        # Set both roots before importing SiftFetch. Only this short-lived CLI
        # process sees the synthetic policy and transport.
        env = {k: v for k, v in os.environ.items() if not k.startswith("SIFTFETCH_")}
        env.update(SIFTFETCH_HOME=str(root), SIFTFETCH_DATA=str(root / "data"))
        with patch.dict(os.environ, env, clear=True):
            (root / "identifiers.json").write_text('{"version":1,"values":[]}', encoding="utf-8")
            (root / "config.json").write_text('{"sightings":"off","browser_fetch":{"mode":"off"}}',
                                               encoding="utf-8")
            print(json.dumps(_measure(args.flows, PAGE_BYTES[args.page]), indent=2))


if __name__ == "__main__":
    main()
