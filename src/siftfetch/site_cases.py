"""Local site aggregates and privacy-checked evidence for offline review."""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import date, datetime, timezone
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from urllib.parse import urlsplit

from siftfetch import domains, egress_policy, injection_scan, saving


_FAILURES = {"http_error", "network_error", "bot_wall", "thin_page", "missing_evidence"}
MAX_EXCERPT_CHARS = 500
_STATUSES = ("unreviewed", "false_positive", "confirmed_instruction", "inconclusive")
_PRIVACY_SIGNAL = re.compile(
    r"[\w.+-]+@[\w.-]+\.[\w-]+|\b\d{3}-\d{2}-\d{4}\b|(?<!\w)(?:\+?\d[ ().-]*){10,}(?!\w)"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"
    r"|\b(?:bearer\s+\S+|(?:api[_-]?key|(?:access[_-]?)?token|password|(?:client[_-]?)?secret|"
    r"signature|session(?:id)?|authorization|private[_-]?key)\s*[:=]\s*\S+)"
    r"|\b(?:[a-z0-9_-]{36,}|[0-9a-f]{20,})\b|(?:(?<!\w)[a-z]:[\\/]|/(?:home|users)/)"
    r"|(?:https?://\S*[?#@]|[?&][\w.-]+=)", re.I)
_TABLE = """CREATE TABLE IF NOT EXISTS site_cases (
    day TEXT NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL,
    risk TEXT NOT NULL, revision TEXT NOT NULL, observations INTEGER NOT NULL,
    PRIMARY KEY (day, site, kind, reason, risk, revision)) WITHOUT ROWID"""
_EVIDENCE = """CREATE TABLE IF NOT EXISTS case_evidence (
    id INTEGER PRIMARY KEY, site TEXT NOT NULL, source_host TEXT NOT NULL, source_path TEXT NOT NULL,
    category TEXT NOT NULL, location TEXT NOT NULL, pattern_id TEXT NOT NULL, excerpt TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'unreviewed',
    UNIQUE(site, source_host, source_path, category, location, pattern_id, excerpt))"""
_EVENTS = """CREATE TABLE IF NOT EXISTS case_observations (
    id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, captured_at TEXT, origin TEXT NOT NULL,
    risk TEXT, revision TEXT, aggregate_reason TEXT NOT NULL)"""
_LINKS = """CREATE TABLE IF NOT EXISTS case_observation_evidence (
    observation_id INTEGER NOT NULL REFERENCES case_observations(id),
    evidence_id INTEGER NOT NULL REFERENCES case_evidence(id),
    PRIMARY KEY(observation_id, evidence_id)) WITHOUT ROWID"""


def _safe(value):
    """Fail closed on decoding/identity checks. Omit the whole field on a match."""
    decoded = egress_policy.decoded_views(value)
    if not decoded.complete or any(_PRIVACY_SIGNAL.search(view) for view in decoded.views):
        return False
    decision = egress_policy.check_text(value, tool="site-cases", session_kind="unattended", log=False)
    return decision.action == "allow" and decision.reason_code == "ok" and not decision.sensitive_host


@lru_cache(maxsize=1)
def _private_rules():
    data = Path(domains.__file__).with_name("public_suffix_list.dat").read_text(encoding="utf-8")
    _, marker, section = data.partition("// ===BEGIN PRIVATE DOMAINS===")
    if not marker:
        raise ValueError("Missing PSL section boundary")
    return {line.encode("idna").decode("ascii").lower() for line in section.splitlines()
            if line and not line.startswith("//")}


def _site(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None:
        return None
    host = domains.normalize_host(parts.hostname)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None
    labels = host.split(".")
    rules = domains._suffixes()
    private = _private_rules()
    known_tld = labels[-1] in rules or "*." + labels[-1] in rules
    if (len(labels) < 2 or not known_tld or egress_policy.destination_allowed(url)
            or egress_policy.cookie_origin_allowed(url)):
        return None
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in private or "!" + suffix in private or (i and "*." + suffix in private):
            return None
    if len(labels) <= domains._suffix_count(labels):
        return None
    site = domains.registrable_domain(host)
    readable_host = host.encode("ascii").decode("idna")
    if _safe(f"{parts.hostname} {host} {readable_host} {site}"):
        return site
    return None


def _db_path():
    base = saving.data_dir().absolute()
    path = base / "site-cases.sqlite3"
    for folder in (base, *base.parents):
        if saving.is_link(folder):
            raise OSError("Unsafe site register directory")
    for name in (path.name, path.name + "-journal", path.name + "-wal", path.name + "-shm"):
        file = base / name
        if saving.is_link(file):
            raise OSError("Unsafe site register file")
        try:
            info = file.stat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("Unsafe site register file")
    return path


@contextmanager
def _writer():
    path = _db_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    path = _db_path()
    with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=2)) as db, db:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        db.execute(_TABLE)
        yield db


def _increment(db, day, site, kind, reason, risk="", revision=""):
    db.execute("""INSERT INTO site_cases VALUES (?, ?, ?, ?, ?, ?, 1)
                  ON CONFLICT(day,site,kind,reason,risk,revision)
                  DO UPDATE SET observations=observations+1""", (day, site, kind, reason, risk, revision))


def record_failure(url, reason):
    """Best-effort recording. A reporting failure must preserve the original read outcome."""
    try:
        if reason not in _FAILURES or egress_policy._config().get("failed_sites") != "on":
            return False
        site = _site(url)
        if not site:
            return False
        with _writer() as db:
            _increment(db, datetime.now(timezone.utc).date().isoformat(), site, "failure", reason)
        return True
    except (OSError, ValueError, sqlite3.Error, egress_policy.PolicyError):
        return False


def _capture_time(value):
    if value is None:
        return None
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Capture time must include a UTC offset")
    return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _source_path(url):
    parts = urlsplit(url)
    path = parts.path or "/"
    if len(path) > 768 or not _safe(path) or not _safe(parts._replace(query="", fragment="").geturl()):
        return ""
    for view in egress_policy.decoded_views(path).views:
        if (any(ord(c) < 32 or c in "?#\\@" for c in view)
                or re.search(r"/(?:users?|profiles?|tenants?|accounts?|invites?|tokens?)/[^/]", view, re.I)):
            return ""
    return path


def _excerpt(text):
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_EXCERPT_CHARS or not _safe(text):
        return ""
    clean = injection_scan.detection_excerpt(text)
    return clean if _safe(clean) else ""


def _evidence_rows(scan, known, patterns):
    rows = set()
    for d in scan.detections[:10]:
        category = d.get("type")
        if category not in known:
            continue
        location = d.get("location", "")
        if location.startswith("hidden:"):
            # The raw HTML can supply arbitrary data-sift-hidden labels.
            suffix = location.removeprefix("hidden:")
            if suffix not in {"comment", "noscript", "aria", "aria-hidden", "hidden element",
                              "fully transparent (opacity)", "text colored like its background",
                              "positioned off-screen", "transparent text color", "unicode-tags"}:
                location = "hidden:other"
        elif location not in ("visible", "attribute"):
            location = "unspecified"
        pattern = d.get("pattern_id", "")
        allowed = {category, "heuristic:" + category}
        allowed.update(f"{category}:{n}" for n in range(1, len(patterns.get(category, ())) + 1))
        pattern = pattern if pattern in allowed else ""
        rows.add((category, location, pattern, _excerpt(d.get("text"))))
    return sorted(rows)


def _observe(url, origin, reason, risk, revision, rows, captured_at):
    site = _site(url)
    if not site:
        return False
    host = domains.normalize_host(urlsplit(url).hostname)
    path = _source_path(url)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    captured_at = _capture_time(captured_at)
    with _writer() as db:
        for ddl in (_EVIDENCE, _EVENTS, _LINKS):
            db.execute(ddl)
        _increment(db, timestamp[:10], site, "candidate", reason, risk or "", revision or "")
        event = db.execute("""INSERT INTO case_observations
            (observed_at, captured_at, origin, risk, revision, aggregate_reason) VALUES (?, ?, ?, ?, ?, ?)""",
                           (timestamp, captured_at, origin, risk, revision, reason)).lastrowid
        for category, location, pattern, excerpt in rows:
            key = (site, host, path, category, location, pattern, excerpt)
            db.execute("""INSERT INTO case_evidence
                (site,source_host,source_path,category,location,pattern_id,excerpt) VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(site,source_host,source_path,category,location,pattern_id,excerpt) DO NOTHING""", key)
            db.execute("""INSERT INTO case_observation_evidence
                SELECT ?, id FROM case_evidence WHERE site=? AND source_host=? AND source_path=? AND category=?
                AND location=? AND pattern_id=? AND excerpt=?""", (event, *key))
    return True


def record_detection(url, scan, *, captured_at=None):
    """Record one transport-verified first read and any qualifying detector excerpts."""
    if not scan.complete or scan.risk not in ("medium", "high-candidate", "high"):
        return False
    try:
        if egress_policy._config().get("case_study_sites") != "on":
            return False
        version, _, patterns = injection_scan._patterns()
        known = set(patterns) | set(injection_scan.REASONS) | {
            "reader_directed_instruction", "encoded_instruction", "removed_content_instruction",
            "tool_instruction", "unicode_obfuscation", "obfuscated", "link_exfil"}
        for location, categories in (("hidden", scan.hidden_categories), ("visible", scan.categories)):
            for category in sorted(known.intersection(categories)):
                rows = _evidence_rows(scan, known, patterns) or [(category, location, "", "")]
                revision = version if scan.patterns_version == version else None
                return _observe(url, "detector", f"{location}:{category}", scan.risk, revision, rows, captured_at)
        return False
    except (OSError, ValueError, sqlite3.Error, egress_policy.PolicyError):
        return False


def record_reported_candidate(*, url, excerpt, captured_at):
    """Persist a host-verified verbatim selection. Manual reports have no detector grade."""
    try:
        if egress_policy._config().get("case_study_sites") != "on":
            return False
        clean = _excerpt(excerpt)
        return bool(clean) and _observe(url, "manual", "manual:reported", None, None,
                                        [("reported", "capture", "", clean)], captured_at)
    except (OSError, ValueError, sqlite3.Error, egress_policy.PolicyError):
        return False


def review(kind, since=None):
    """Read the register offline, with an optional inclusive UTC date."""
    if kind not in ("failure", "candidate"):
        raise ValueError("Unknown register")
    start = date.fromisoformat(since).isoformat() if since else "0001-01-01"
    path = _db_path()
    if not path.exists():
        return []
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA trusted_schema=OFF")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='site_cases'").fetchone():
            return []
        return [dict(row) for row in db.execute("""
            SELECT site, reason, risk, revision, min(day) AS first_seen, max(day) AS last_seen,
                   sum(observations) AS observations FROM site_cases
            WHERE kind=? AND day>=? GROUP BY site, reason, risk, revision
            ORDER BY last_seen DESC, site, reason, risk, revision""", (kind, start))]


def review_evidence(*, since=None, site=None):
    """Group distinct evidence and its UTC observations within the requested window."""
    start = date.fromisoformat(since).isoformat() if since else ""
    path = _db_path()
    if not path.exists():
        return []
    groups = {}
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA trusted_schema=OFF")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_evidence'").fetchone():
            return []
        rows = db.execute("""SELECT e.id AS evidence_id, e.site, e.source_host, e.source_path,
            e.category, e.location, e.pattern_id, e.excerpt, e.review_status, o.id AS event_id,
            o.observed_at, o.captured_at, o.origin, o.risk, o.revision
            FROM case_evidence e JOIN case_observation_evidence l ON l.evidence_id=e.id
            JOIN case_observations o ON o.id=l.observation_id
            WHERE o.observed_at>=? AND (? IS NULL OR e.site=?) ORDER BY o.observed_at, o.id, e.id""",
                          (start, site, site))
        for row in rows:
            key = row["evidence_id"]
            if key not in groups:
                groups[key] = {name: row[name] or None for name in
                               ("evidence_id", "site", "source_host", "source_path", "category",
                                "location", "pattern_id", "excerpt", "review_status")}
                groups[key].update(first_seen=row["observed_at"], observations=0, history=[])
            item = groups[key]
            item["last_seen"] = row["observed_at"]
            item["observations"] += 1
            item["history"].append({k: row[k] for k in ("event_id", "observed_at", "captured_at",
                                                        "origin", "risk", "revision")})
    return list(groups.values())


def classify_evidence(evidence_id, status):
    """Record an explicit reviewer judgment for one existing piece of evidence."""
    if status not in _STATUSES:
        raise ValueError("Unknown review status")
    path = _db_path()
    if not path.exists():
        return False
    with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=2)) as db, db:
        db.execute("PRAGMA trusted_schema=OFF")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_evidence'").fetchone():
            return False
        return db.execute("UPDATE case_evidence SET review_status=? WHERE id=?", (status, evidence_id)).rowcount == 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="kind", required=True)
    for kind in ("failure", "candidate", "evidence"):
        command = commands.add_parser(kind)
        command.add_argument("--since", metavar="YYYY-MM-DD")
        if kind == "evidence":
            command.add_argument("--site")
    classify = commands.add_parser("classify")
    classify.add_argument("evidence_id", type=int)
    classify.add_argument("status", choices=_STATUSES)
    args = parser.parse_args()
    if args.kind == "evidence":
        result = review_evidence(since=args.since, site=args.site)
    elif args.kind == "classify":
        if not classify_evidence(args.evidence_id, args.status):
            parser.error("Evidence ID is unavailable")
        result = {"evidence_id": args.evidence_id, "review_status": args.status}
    else:
        result = review(args.kind, args.since)
    print(json.dumps(result, indent=2, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e"))


if __name__ == "__main__":
    main()
