import json

import pytest

from siftfetch import egress_policy as ep


@pytest.mark.parametrize("config,field", [
    ({"guard_lock": "yes"}, "guard_lock"),
    ({"guard_lock": None}, "guard_lock"),
    ({"guard_lock": {"enabled": 1}}, "guard_lock.enabled"),
    ({"guard_lock": {"paths": [7]}}, "guard_lock.paths"),
    ({"secret_file_mode": "loose"}, "secret_file_mode"),
    ({"local_endpoints": {}}, "local_endpoints"),
    ({"local_endpoints": [{"scheme": "http", "host": "localhost", "port": True}]}, "port"),
    ({"local_endpoints": [{"scheme": "http", "host": 7, "port": 80}]}, "host"),
    ({"cookie_origins": "https://example.test"}, "cookie_origins"),
    ({"cookie_origins": [1]}, "cookie_origins"),
    ({"cookies_attended_only": "false"}, "cookies_attended_only"),
    ({"mcp_local_tools": [3]}, "mcp_local_tools"),
])
def test_bad_security_config(tmp_path, monkeypatch, config, field):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text('{"values": []}', encoding="utf-8")
    (tmp_path / "config.json").write_text(json.dumps(config), encoding="utf-8")
    decision = ep.check_search("ordinary documentation")
    assert decision.action == "deny" and field in decision.label
    assert "config.json" in decision.label
    assert ep.guard_lock_state()[0]
    with pytest.raises(ep.PolicyError):
        ep._config()


@pytest.mark.parametrize("field,value", [("label", 1), ("kind", []), ("kind", "other"),
                                         ("value", 1), ("class", "public"),
                                         ("public_search", "false"), ("match", "auto")])
def test_bad_identifiers(field, value):
    entry = {"label": "test", "kind": "text", "value": "Synthetic", "class": "exact"}
    entry[field] = value
    with pytest.raises(ep.PolicyError, match=field):
        ep.validate_policy("identifiers.json", {"values": [entry]})


@pytest.mark.parametrize("values", [None, {}, "text", [1]])
def test_bad_identifier_collection(values):
    with pytest.raises(ep.PolicyError, match="values"):
        ep.validate_policy("identifiers.json", {"values": values})


def test_empty_values_and_invalid_grants(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text('{"values": []}', encoding="utf-8")
    (tmp_path / "exceptions.json").write_text('{"exceptions": [null, {"label": 1}]}', encoding="utf-8")
    with pytest.warns(UserWarning, match="ignored 2 invalid grants"):
        assert ep.check_search("ordinary text").action == "allow"
