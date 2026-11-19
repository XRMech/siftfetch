"""Explicit reporter observations must come from the caller's public capture."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
import json
import sqlite3

import httpx
import pytest

from siftfetch import research_flow, site_cases, tools
from siftfetch.research_flow import ResearchFlow, SnapshotUnavailable


@pytest.fixture
def observation(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    (tmp_path / "identifiers.json").write_text('{"version":1,"values":[]}')
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"case_study_sites": "on"}))
    fetched = []
    body = ("<main><p>Record rain &amp; wind at station.</p><p>" + "Field notes. " * 80
            + "</p></main><!-- fixture note visible in the HTML -->")

    def fetch(url, **kwargs):
        fetched.append(url)
        return httpx.Response(200, request=httpx.Request("GET", url),
                              headers={"Content-Type": "text/html", "Cache-Control": "public"},
                              extensions={"siftfetch_public_direct": True}, content=body.encode())

    monkeypatch.setattr(tools, "fetch", fetch)
    with ResearchFlow() as flow:
        page = flow.fetch("https://reports.example.co.uk/reference")
        assert page.handle and "risk=none" in page.content
        yield flow, page, fetched, config


def test_report_exact_source_and_cleaned_text(observation, monkeypatch):
    flow, page, fetched, _ = observation
    events = []
    def store(**values):
        events.append(values)
        return True
    monkeypatch.setattr(site_cases, "record_reported_candidate", store)
    excerpts = ("fixture note visible in the HTML", "rain & wind at station")
    for text in excerpts:
        assert flow.report_candidate(page.handle, text)
        assert not flow.report_candidate(page.handle, text)
    assert events == [{"url": fetched[0], "excerpt": text, "captured_at": page.captured_at}
                      for text in excerpts]
    assert len(fetched) == 1


def test_report_scope_validation_and_opt_out(observation, monkeypatch):
    flow, page, _, config = observation
    monkeypatch.setattr(site_cases, "record_reported_candidate",
                        lambda **kwargs: pytest.fail("Invalid or disabled report reached storage"))
    with ResearchFlow() as other, pytest.raises(SnapshotUnavailable):
        other.report_candidate(page.handle, "Field notes.")
    for invalid in (None, "", "   ", "x" * 501, "a description supplied by the caller"):
        with pytest.raises(ValueError):
            flow.report_candidate(page.handle, invalid)
    config.write_text('{"case_study_sites":"off"}')
    assert not flow.report_candidate(page.handle, "Field notes.")
    flow.release()
    with pytest.raises(SnapshotUnavailable):
        flow.report_candidate(page.handle, "Field notes.")


def test_report_retry_and_concurrent_deduplication(observation, monkeypatch):
    flow, page, _, _ = observation
    responses = iter((False, True))
    monkeypatch.setattr(site_cases, "record_reported_candidate", lambda **kwargs: next(responses))
    assert not flow.report_candidate(page.handle, "Field notes.")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: flow.report_candidate(page.handle, "Field notes."), range(8)))
    assert results.count(True) == 1


def test_manual_observation_persists_without_detector_grade(observation):
    flow, page, fetched, _ = observation
    text = "rain & wind at station"
    assert flow.report_candidate(page.handle, text)
    assert not flow.report_candidate(page.handle, text)
    with closing(sqlite3.connect(site_cases._db_path())) as db:
        events = db.execute("SELECT origin, risk, captured_at FROM case_observations").fetchall()
        rows = db.execute("SELECT excerpt, review_status FROM case_evidence").fetchall()
    assert len(events) == 1 and events[0][:2] == ("manual", None)
    assert datetime.fromisoformat(events[0][2]) == datetime.fromisoformat(page.captured_at)
    assert rows == [(text, "unreviewed")]
    assert len(fetched) == 1


def test_capture_report_budget(observation, monkeypatch):
    flow, page, _, _ = observation
    monkeypatch.setattr(research_flow, "_MAX_REPORTS_PER_CAPTURE", 2)
    assert flow.report_candidate(page.handle, "Field notes.")
    assert flow.report_candidate(page.handle, "rain & wind")
    assert not flow.report_candidate(page.handle, "at station")
    assert site_cases.review("candidate")[0]["observations"] == 2
