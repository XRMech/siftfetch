"""Summarize local research observations by UTC month, origin, detector revision and category."""
import argparse
from datetime import datetime, timezone
import json

from siftfetch import site_cases


def summarize(evidence):
    groups = {}
    for case in evidence:
        for observation in case["history"]:
            stamp = datetime.fromisoformat(observation["observed_at"].replace("Z", "+00:00"))
            month = stamp.astimezone(timezone.utc).strftime("%Y-%m")
            key = (month, observation["origin"], observation.get("revision") or "", case["category"])
            bucket = groups.setdefault(key, {"events": set(), "sites": set(), "evidence": set(),
                                             "observations": 0, "with_excerpt": 0})
            bucket["events"].add(observation["event_id"])
            bucket["sites"].add(case["site"])
            bucket["evidence"].add(case["evidence_id"])
            bucket["observations"] += 1
            if case["excerpt"]:
                bucket["with_excerpt"] += 1
    return [
        {"month_utc": month, "origin": origin, "revision": revision or None, "category": category,
         "observation_events": len(bucket["events"]), "unique_sites": len(bucket["sites"]),
         "unique_evidence_records": len(bucket["evidence"]), "excerpt_observations": bucket["with_excerpt"],
         "observations_without_excerpt": bucket["observations"] - bucket["with_excerpt"]}
        for (month, origin, revision, category), bucket in sorted(groups.items())
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", metavar="YYYY-MM-DD")
    parser.add_argument("--site", metavar="DOMAIN")
    args = parser.parse_args()
    rows = site_cases.review_evidence(since=args.since, site=args.site)
    print(json.dumps(summarize(rows), indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
