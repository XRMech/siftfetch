import base64
import json
import time

import pytest

from siftfetch import egress_policy as ep

VALUE = "synthetic@mail.test"


def b64(value):
    return base64.b64encode(value.encode()).decode()


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(json.dumps({"values": [
        {"label": "canary", "kind": "email", "value": VALUE, "class": "exact"}
    ]}), encoding="utf-8")


@pytest.mark.parametrize("encoded", [
    b64(VALUE + "\n"), b64(VALUE.replace("@", "%40")),
    b64(VALUE.replace("@", "&#64;")), b64(VALUE.replace("@", "＠")),
    *[sep.join(b64(VALUE)[i:i + 4] for i in range(0, len(b64(VALUE)), 4))
      for sep in ("%E2%80%8B", "%20", ".")],
    "A" * 4092 + b64(VALUE), b64(b64(VALUE)), VALUE.encode().hex(),
    base64.b32encode(VALUE.encode()).decode(),
    b64("\x00" * 10 + VALUE + "\x01" * 10),
])
def test_encoded_attacks(policy, encoded):
    decision = ep.check_url("https://docs.example/", extra=[("header:x", encoded)])
    assert decision.action == "deny", encoded


def test_shared_budget_denies(policy, monkeypatch):
    monkeypatch.setattr(ep, "MAX_DECODE_BYTES", 20)
    d = ep.check_url("https://docs.example/", extra=[("header:x", b64("ordinary text")),
                                                        ("header:y", b64("different text"))])
    assert d.reason_code == "could_not_check"


def test_benign_decode_performance(policy):
    body = ("Documentation testing sample 0123456789abcdef " * 24000)[:999000]
    start = time.perf_counter()
    assert ep.check_url("https://docs.example/", extra=[("body", body)]).action == "allow"
    assert time.perf_counter() - start < 2
    batch = json.dumps([{"title": "Reference documentation", "body": "Ordinary API examples " * 30}
                        for _ in range(290)])
    start = time.perf_counter()
    assert ep.check_url("https://docs.example/", extra=[("body", batch)]).action == "allow"
    assert time.perf_counter() - start < 1


def test_json_leaf_compaction(policy):
    encoded = ".".join(b64(VALUE)[i:i + 4] for i in range(0, len(b64(VALUE)), 4))
    assert ep.check_url("https://docs.example/", extra=[("body", json.dumps({"x": encoded}))]).action == "deny"
    assert ep.check_search("commit 0123456789abcdef0123456789abcdef01234567").action == "allow"
