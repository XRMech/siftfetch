import base64
import inspect
import json

import pytest

from siftfetch import egress_policy as ep


def test_public_signatures():
    assert ep.API_VERSION == 1
    assert list(inspect.signature(ep.identifier_pattern).parameters) == ["kind", "value", "match"]
    assert inspect.signature(ep.identifier_pattern).parameters["match"].default == "auto"
    assert list(inspect.signature(ep.decoded_views).parameters) == ["text", "budget"]
    assert inspect.signature(ep.decoded_views).parameters["budget"].default is None


def test_public_api_attack_and_control():
    value = "synthetic@mail.test"
    pattern = ep.identifier_pattern("email", value)
    encoded = base64.b64encode(value.encode()).decode()
    result = ep.decoded_views(encoded)
    assert result.complete and any(pattern.search(v) for v in result.views)
    assert not any(pattern.search(v) for v in ep.decoded_views("ordinary documentation").views)
    assert ep.decoded_views(encoded, budget=0).complete is False


@pytest.mark.parametrize("kind,value,attack,benign", [
    ("text", "Morgan Example", "xxMorganExampleyy", "Morgan samples"),
    ("phone", "5550104477", "99555010447788", "2026-10-26 12:34:56 port 443 v3.11 ID 5550104478"),
    ("email", "synthetic@mail.test", "xxsynthetic@mail.testyy", "synthetic2@mail.test"),
])
def test_padded_exact_identifiers(tmp_path, monkeypatch, kind, value, attack, benign):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path))
    monkeypatch.setattr(ep, "_cached", None)
    (tmp_path / "identifiers.json").write_text(json.dumps({"values": [
        {"label": "synthetic", "kind": kind, "value": value, "class": "exact"}
    ]}), encoding="utf-8")
    assert ep.check_search(attack).action == "deny"
    assert ep.check_search(benign).action == "allow"


def test_word_and_substring_modes():
    assert not ep.identifier_pattern("text", "Lee Ann").search("fleeAnnual")
    assert ep.identifier_pattern("text", "Lee Ann", "substring").search("fleeAnnual")
    assert not ep.identifier_pattern("text", "Morgan Example", "word").search("xMorganExampley")
    assert ep.identifier_pattern("text", "Lee Ann").search("Lee Ann")


_MAIL_DOMAIN = 'gmail' + '.com'


@pytest.mark.parametrize("address", [f"janedoe@{_MAIL_DOMAIN}", f"j.a.n.e.d.o.e@{_MAIL_DOMAIN}",
                                     "jane.doe+news@googlemail.com", f"janedoe+tag@{_MAIL_DOMAIN}"])
def test_deliverable_email_variants(address):
    assert ep.identifier_pattern("email", f"jane.doe@{_MAIL_DOMAIN}").search(address)
    assert not ep.identifier_pattern("email", f"jane.doe@{_MAIL_DOMAIN}").search(f"janedoer@{_MAIL_DOMAIN}")


@pytest.mark.parametrize("separator", [" ", ".", "-", "(", ")", "/", "_", ",", " /_"])
def test_phone_separators(separator):
    pattern = ep.identifier_pattern("phone", "5550104477")
    assert pattern.search(separator.join("5550104477"))
    assert not pattern.search(separator.join("5550104478"))
    assert not pattern.search("----".join("5550104477"))


def test_decoded_email_tag():
    encoded = base64.b64encode(b"synthetic+news@mail.test").decode()
    pattern = ep.identifier_pattern("email", "synthetic@mail.test")
    assert any(pattern.search(v) for v in ep.decoded_views(encoded).views)
