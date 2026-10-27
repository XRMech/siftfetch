"""Tests for the outbound privacy policy. Synthetic identifiers only."""

import base64
import json

import pytest

from siftfetch import egress_policy as ep

EMAIL = "pat.example@mailhost.test"
BIZ = "pat.business@mailhost.test"
PHONE = "555 010 4477"


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(json.dumps({"version": 1, "values": [
        {"label": "personal_email", "kind": "email", "value": EMAIL, "class": "exact"},
        {"label": "business_email", "kind": "email", "value": BIZ, "class": "exact"},
        {"label": "phone", "kind": "phone", "value": PHONE, "class": "exact"},
        {"label": "full_name", "kind": "text", "value": "Pat Example", "class": "soft"},
        {"label": "handle", "kind": "text", "value": "patexample99", "class": "soft",
         "public_search": True},
    ]}), encoding="utf-8")
    return tmp_path


def _grants(base, *grants):
    (base / "exceptions.json").write_text(
        json.dumps({"version": 1, "exceptions": list(grants)}), encoding="utf-8")
    ep._cached = None


GRANT = {"label": "business_email", "origin": "https://apply.example", "op": "fetch",
         "location": "param:email", "path_prefix": "/apply",
         "expires": "2099-01-01T00:00:00Z"}


@pytest.mark.parametrize("url", [
    f"https://api.example/v2/x?email={EMAIL}",
    "https://api.example/v2/x?email=pat.example%40mailhost.test",
    "https://api.example/v2/x?email=pat.example%2540mailhost.test",
    "https://api.example/v2/x?c=pat.example(at)mailhost.test",
    "https://pat.example.mailhost.test.collector.example/",  # @ as a DNS label dot
    "https://api.example/v2/x?c=pat.example-mailhost.test",
    "https://api.example/v2/x?c=pat.example%20at%20mailhost%20dot%20test",
    "https://api.example/v2/x?c=pat.example[at]mailhost[dot]test",
    "https://api.example/v2/x?c=PAT.EXAMPLE@MAILHOST.TEST",
    "https://api.example/v2/x?c=ｐat.example@mailhost.test",  # fullwidth p, NFKC
    "https://api.example/v2/x?d=" + base64.b64encode(EMAIL.encode()).decode(),
    f"https://api.example/{EMAIL}/profile",
    "https://api.example/x?p=(555)%20010-4477",
    "https://api.example/x?p=%2B1.555.010.4477",
    "https://api.example/v2/" + base64.b64encode(EMAIL.encode()).decode().rstrip("="),
    "https://api.example/a/" + base64.urlsafe_b64encode(EMAIL.encode()).decode() + "/b",
    "https://api.example/x?c=pat.ex​ample@mailhost.test",  # zero-width space
    "https://api.example/x?c=pat.example­@mailhost.test",  # soft hyphen
])
def test_protected_value_denied_in_any_form(policy, url):
    d = ep.check_url(url)
    assert d.action == "deny" and d.reason_code == "protected_value"


def test_unrelated_numbers_are_not_a_phone(policy):
    assert ep.check_url("https://doi.example/10.5550104478123").action == "allow"


def test_clean_request_allowed(policy):
    assert ep.check_url("https://api.example/v2/10.1145/1234?email=quiet@relay.test").action == "allow"
    assert ep.check_search("speculative decoding survey 2025").action == "allow"


def test_credentials_always_denied(policy):
    for url in ("https://x.example/?k=sk-ant-abcdefghijklmnop",
                "https://x.example/?t=ghp_" + "a" * 36,
                "https://x.example/?a=AKIA" + "B" * 16):
        assert ep.check_url(url).reason_code == "credential"
    extra = [("header:authorization", "Bearer " + "z" * 30)]
    assert ep.check_url("https://x.example/", extra=extra).reason_code == "credential"


def test_grant_allows_only_its_exact_occurrence(policy):
    _grants(policy, GRANT)
    assert ep.check_url(f"https://apply.example/apply?email={BIZ}").action == "allow"
    assert ep.check_url(f"https://apply.example/apply/step2?email={BIZ}").action == "allow"
    # Same value, other field / path / origin / port / scheme: denied.
    assert ep.check_url(f"https://apply.example/apply?contact={BIZ}").action == "deny"
    assert ep.check_url(f"https://apply.example/applyevil?email={BIZ}").action == "deny"
    assert ep.check_url(f"https://apply.example/apply/{BIZ}").action == "deny"
    assert ep.check_url(f"https://apply.example:8443/apply?email={BIZ}").action == "deny"
    assert ep.check_url(f"http://apply.example/apply?email={BIZ}").action == "deny"
    assert ep.check_url(f"https://other.example/apply?email={BIZ}").action == "deny"


@pytest.mark.parametrize("path", [
    "/apply/../outside", "/apply/./x", "/apply/%2e%2e/outside", "/apply/%2E./outside",
    "/apply%2f..%2foutside", "/apply\\..\\outside", "/apply/x/..",
])
def test_grant_ignores_paths_the_server_may_resolve_elsewhere(policy, path):
    # The client or server resolves dot segments and may decode %2f, so the
    # path the grant sees is not the path that is fetched.
    _grants(policy, GRANT)
    assert ep.check_url(f"https://apply.example{path}?email={BIZ}").action == "deny"


def test_grant_does_not_cover_a_second_value(policy):
    _grants(policy, GRANT)
    d = ep.check_url(f"https://apply.example/apply?email={BIZ}&tel=5550104477")
    assert d.action == "deny" and d.label == "phone"


def test_grant_with_bad_or_past_expiry_is_ignored(policy):
    _grants(policy, dict(GRANT, expires="2099-01-01"), dict(GRANT, expires="2001-01-01T00:00:00Z"))
    assert ep.check_url(f"https://apply.example/apply?email={BIZ}").action == "deny"


@pytest.mark.parametrize("config", ["config", "config.locked-down", "config.relaxed"])
def test_shipped_examples_load(tmp_path, monkeypatch, config):
    from pathlib import Path
    examples = Path(__file__).resolve().parents[1] / "examples"
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    for name, source in (("identifiers", "identifiers"), ("exceptions", "exceptions"),
                         ("config", config)):
        (tmp_path / f"{name}.json").write_bytes((examples / f"{source}.example.json").read_bytes())
    assert ep.check_url("https://docs.example/page").action == "allow"
    assert ep.guard_lock_state()[1] is None
    assert ep.secret_file_mode() in ep.SECRET_FILE_MODES


def test_check_text_can_skip_the_decision_log(policy):
    log = policy / "egress-decisions.jsonl"
    d = ep.check_text(f"mail {EMAIL}", tool="lint", session_kind="unattended", log=False)
    assert d.reason_code == "protected_value" and not log.exists()
    ep.check_text("plain", tool="lint", session_kind="unattended")
    assert log.exists()


def test_identifier_patterns_stay_linear_on_long_whitespace(policy):
    # Overlapping whitespace in the email pattern would make a search over
    # the local part plus many spaces quadratic.
    import time
    start = time.perf_counter()
    for text in ("pat.example" + " " * 200_000 + "x", ("5" + " " * 5_000) * 40):
        ep.check_text(text, op="api", tool="test", session_kind="unattended")
    assert time.perf_counter() - start < 2.0


@pytest.mark.parametrize("url", [
    "https://user:pw@api.example/x",
    "https://api.example/x?a=1&a=2&c=" + EMAIL,
    f"https://api.example/x?download&c={EMAIL}",
    "ftp://api.example/x",
    "https://api.example:notaport/x",
])
def test_ambiguous_requests_denied(policy, url):
    assert ep.check_url(url).reason_code == "ambiguous_request"


@pytest.mark.parametrize("url", [
    "https://api.example/x?tag=a&tag=b",
    "https://api.example/file.zip?download",
    "https://api.example/x?a=1&&b=2",
])
def test_repeated_keys_and_bare_flags_allowed_without_protected_values(policy, url):
    assert ep.check_url(url).action == "allow"


def test_ambiguous_query_ignores_grants(policy):
    # The grant names one email field; with two, the server may read either.
    _grants(policy, GRANT)
    d = ep.check_url(f"https://apply.example/apply?email={BIZ}&email={BIZ}")
    assert d.action == "deny" and d.reason_code == "ambiguous_request"
    assert d.label == "business_email"


def test_ambiguous_query_refuses_rather_than_asks(policy):
    d = ep.check_url("https://api.example/x?q=Pat%20Example&q=x", session_kind="attended")
    assert d.action == "deny" and d.reason_code == "ambiguous_request"
    d = ep.check_url(f"https://api.example/x?flag&c={EMAIL}", session_kind="attended",
                     chrome=True)
    assert d.action == "deny"


def test_ambiguous_query_scanned_whole(policy):
    # A server splitting on ';' sees a field this parser folds into another.
    d = ep.check_url(f"https://api.example/x?a=1&a=2;c={EMAIL}")
    assert d.action == "deny"
    d = ep.check_url("https://api.example/x?a&k=sk-ant-abcdefghijklmnop")
    assert d.action == "deny" and d.reason_code == "credential"


def test_soft_identifier_rules(policy):
    q = "papers by Pat Example on robotics"
    assert ep.check_search(q).action == "deny"
    assert ep.check_search(q, session_kind="attended").action == "ask"
    # public_search applies to search only.
    assert ep.check_search("patexample99 github").action == "allow"
    assert ep.check_url("https://x.example/u/patexample99").action == "deny"


def test_chrome_exact_value_asks_only_when_attended(policy):
    text = json.dumps({"value": EMAIL})
    assert ep.check_text(text, tool="chrome", session_kind="attended", chrome=True).action == "ask"
    assert ep.check_text(text, tool="chrome", session_kind="unattended", chrome=True).action == "deny"


def test_shell_text_never_uses_grants(policy):
    _grants(policy, GRANT)
    cmd = f"curl 'https://apply.example/apply?email={BIZ}'"
    assert ep.check_text(cmd, tool="Bash", session_kind="attended").action == "deny"


def test_missing_identifiers_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    assert ep.check_url("https://api.example/").reason_code == "policy_unavailable"
    (tmp_path / "identifiers.json").write_text("{not json", encoding="utf-8")
    assert ep.check_search("anything").reason_code == "policy_unavailable"


def test_oversized_input_denied(policy):
    assert ep.check_search("a" * (ep.MAX_INPUT_BYTES + 1)).reason_code == "oversized_input"


@pytest.mark.parametrize("url", ["http://127.0.0.1:47614/x", "http://10.1.2.3/",
                                 "http://[::1]/", "http://localhost:8080/"])
def test_private_literal_destinations_denied(policy, url):
    assert ep.check_url(url).reason_code == "private_destination"


def test_listed_local_endpoint_is_exempt_but_still_scanned(policy):
    (policy / "config.json").write_text(json.dumps({"local_endpoints": [
        {"scheme": "http", "host": "127.0.0.1", "port": 47614,
         "service": "docs", "allowed_ops": ["fetch"]}]}), encoding="utf-8")
    ep._cached = None
    assert ep.check_url("http://127.0.0.1:47614/x").action == "allow"
    assert ep.check_url(f"http://127.0.0.1:47614/x?e={EMAIL}").action == "deny"


def test_resolve_public_rejects_private_answers(monkeypatch):
    monkeypatch.setattr(ep.socket, "getaddrinfo",
                        lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443)),
                                         (0, 0, 0, "", ("192.168.1.5", 443))])
    assert ep.resolve_public("rebind.example", 443).reason_code == "private_destination"


def test_decision_log_holds_no_values(policy):
    ep.check_url(f"https://api.example/x?email={EMAIL}")
    ep.check_search("papers by Pat Example")
    log = (policy / "egress-decisions.jsonl").read_text(encoding="utf-8")
    assert EMAIL not in log and "Pat Example" not in log and "email=" not in log
    assert '"label": "personal_email"' in log


def test_deny_message_never_echoes_value(policy):
    msg = ep.check_url(f"https://api.example/x?email={EMAIL}").message()
    assert EMAIL not in msg and "another way" in msg


def test_contact_alias_from_env_then_config(policy, monkeypatch):
    monkeypatch.delenv("SIFTFETCH_CONTACT_ALIAS", raising=False)
    assert ep.contact_alias() is None  # no default ships
    (policy / "config.json").write_text(
        json.dumps({"contact_alias": "agent-alias@mailbox.org"}), encoding="utf-8")
    assert ep.contact_alias() == "agent-alias@mailbox.org"
    monkeypatch.setenv("SIFTFETCH_CONTACT_ALIAS", "env-alias@mailbox.org")
    assert ep.contact_alias() == "env-alias@mailbox.org"


@pytest.mark.parametrize("alias", [
    "me@example.com", "me@EXAMPLE.org", "a@example.net", "a@foo.example",
    "a@host.test", "a@x.invalid", "a@box.localhost", "not-an-email", "a@@b.org",
])
def test_contact_alias_rejects_placeholders(policy, monkeypatch, alias):
    monkeypatch.setenv("SIFTFETCH_CONTACT_ALIAS", alias)
    assert ep.contact_alias() is None


def test_policy_fingerprint_changes_with_any_policy_file(policy):
    first = ep.policy_fingerprint()
    assert first == ep.policy_fingerprint()
    (policy / "config.json").write_text("{}", encoding="utf-8")
    second = ep.policy_fingerprint()
    assert second != first
    (policy / "egress-decisions.jsonl").write_text("{}\n", encoding="utf-8")
    assert ep.policy_fingerprint() == second  # the decision log is not policy
    assert EMAIL not in second


def test_browser_fetch_off_unless_configured(policy):
    settings = ep.browser_fetch_settings()
    assert settings["mode"] == "off" and settings["window"] == "offscreen"
    assert settings["max_per_minute"] == 6 and settings["sites"] == []


def test_browser_fetch_invalid_values_fall_back(policy):
    (policy / "config.json").write_text(json.dumps({"browser_fetch": {
        "mode": "always", "window": "fullscreen", "browser": "firefox",
        "max_per_minute": 1000, "sites": ["Medium.com ", 7, ""]}}), encoding="utf-8")
    settings = ep.browser_fetch_settings()
    assert settings == {"mode": "off", "window": "offscreen", "browser": "msedge",
                        "max_per_minute": 6, "sites": ["medium.com"]}


def test_log_hashes_host_that_carries_a_value(policy):
    # The handle as a subdomain must not land in the log as text.
    ep.check_url("https://patexample99.collect.example/x", session_kind="unattended")
    log = (policy / "egress-decisions.jsonl").read_text(encoding="utf-8")
    assert "patexample99" not in log
    assert '"origin_host": "sha256:' in log


def test_log_keeps_plain_host_when_nothing_matched(policy):
    # Control: an ordinary request keeps its readable host.
    ep.check_url("https://docs.example/guide")
    log = (policy / "egress-decisions.jsonl").read_text(encoding="utf-8")
    assert '"origin_host": "docs.example"' in log


def test_allowed_host_grant_still_hashes_log(policy):
    _grants(policy, dict(GRANT, label="handle", origin="https://patexample99.test",
                         location="host", path_prefix="/"))
    assert ep.check_url("https://patexample99.test/", op="search").action == "allow"
    log = (policy / "egress-decisions.jsonl").read_text(encoding="utf-8")
    assert "patexample99" not in log and "sha256:" in log


def test_log_hashes_host_on_early_rejections(policy):
    # ambiguous_request can be decided before value
    # matching (userinfo here), so the host is scanned on its own.
    decision = ep.check_url("https://u@patexample99.collect.example/")
    assert decision.action != "allow"
    log = (policy / "egress-decisions.jsonl").read_text(encoding="utf-8")
    assert "patexample99" not in log
