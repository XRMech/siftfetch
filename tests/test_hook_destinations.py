import json
import threading

import pytest

from siftfetch import egress_policy as ep


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(json.dumps({"values": [
        {"label": "canary", "kind": "text", "value": "syntheticprivate", "class": "exact"}
    ]}), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("host", ["127.1", "2130706433", "0x7f000001", "0177.0.0.1",
                                  "[::1]", "[::ffff:127.0.0.1]", "169.254.1.1"])
def test_private_spellings(policy, host):
    assert ep.check_url(f"http://{host}/", resolve_host=True).reason_code == "private_destination"


def test_dns_and_prelookup_value_check(policy, monkeypatch):
    calls = []
    def lookup(*args, **kwargs):
        calls.append(args)
        return [(0, 0, 0, "", (a, 443)) for a in ("93.184.216.34", "10.0.0.1")]
    monkeypatch.setattr(ep.socket, "getaddrinfo", lookup)
    assert ep.check_url("https://syntheticprivate.example/", resolve_host=True).action == "deny"
    assert not calls
    assert ep.check_url("https://docs.example/", resolve_host=True).reason_code == "private_destination"
    assert ep.check_url("https://docs.example/?download", resolve_host=True).reason_code == "private_destination"
    monkeypatch.setattr(ep.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443))])
    assert ep.check_url("https://docs.example/", resolve_host=True).action == "allow"


def test_timeout_failure_and_local_exemption(policy, monkeypatch):
    monkeypatch.setattr(ep, "_HOOK_DNS_TIMEOUT", .01)
    release = threading.Event()
    monkeypatch.setattr(ep.socket, "getaddrinfo", lambda *a, **k: release.wait(.1) and [])
    assert ep.check_url("https://docs.example/", resolve_host=True).reason_code == "destination_unconfirmed"
    release.set()
    monkeypatch.setattr(ep.socket, "getaddrinfo", lambda *a, **k: [])
    assert ep.check_url("https://docs.example/", resolve_host=True).reason_code == "destination_unconfirmed"
    (policy / "config.json").write_text(json.dumps({"local_endpoints": [
        {"scheme": "https", "host": "docs.example", "port": 443}]}), encoding="utf-8")
    ep._cached = None
    assert ep.check_url("https://docs.example/", resolve_host=True).action == "allow"
