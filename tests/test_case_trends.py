from siftfetch.case_trends import summarize


def test_distinguishes_repeat_reads_distinct_evidence_and_detector_revisions():
    def observation(day, event, revision="inj-a", origin="detector"):
        return {"observed_at": f"2026-{day}T12:00:00Z", "event_id": event,
                "origin": origin, "revision": revision}

    first = observation("10-31", "page-read-1")
    second = observation("10-31", "page-read-2")
    evidence = [
        {"evidence_id": "a", "site": "one.example", "category": "exec", "excerpt": "Example.", "history": [
            first, second, observation("11-01", "page-read-3", "inj-b")]},
        {"evidence_id": "b", "site": "one.example", "category": "exec", "excerpt": None, "history": [first]},
        {"evidence_id": "c", "site": "two.example", "category": "reported", "excerpt": "Selected.",
         "history": [observation("11-02", "report-1", None, "manual")]},
    ]
    october, november, manual = summarize(evidence)
    assert october == {"month_utc": "2026-10", "origin": "detector", "revision": "inj-a",
                       "category": "exec", "observation_events": 2, "unique_sites": 1,
                       "unique_evidence_records": 2, "excerpt_observations": 2,
                       "observations_without_excerpt": 1}
    assert november["month_utc"] == "2026-11" and november["revision"] == "inj-b"
    assert manual["origin"] == "manual" and manual["revision"] is None
    assert summarize([]) == []
