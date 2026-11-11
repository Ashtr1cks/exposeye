import json

import pytest
from fastapi.testclient import TestClient

from domainscope.emailcheck import _breach_findings, advice
from domainscope.modules.breaches import normalise_hibp, normalise_xon
from domainscope.modules.email_identity import gravatar_hash, provider_type
from domainscope.modules.passwords import count_in_range, split_hash
from domainscope.report import report_name, to_html, to_markdown
from domainscope.settings import Settings, mask
from domainscope.utils import normalize_email
from domainscope.web.server import create_app

# ---------------------------------------------------------------- normalisation


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("You@Example.COM", "you@example.com"),
        ("  mailto:a.b+tag@sub.example.org ", "a.b+tag@sub.example.org"),
        ("x@bücher.de", "x@xn--bcher-kva.de"),
    ],
)
def test_normalize_email(raw, expected):
    assert normalize_email(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "plain", "@example.com", "a@", "a..b@x.com", ".a@x.com", "a b@x.com", "a@localhost"]
)
def test_normalize_email_rejects(raw):
    with pytest.raises(ValueError):
        normalize_email(raw)


# ---------------------------------------------------------------- passwords (k-anonymity)


def test_split_hash_known_value():
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    assert split_hash("password") == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")


def test_count_in_range():
    body = (
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\nABC:0"
    )
    assert count_in_range(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8") == 9659365
    assert count_in_range(body, "FFFF") == 0


# ---------------------------------------------------------------- breach normalisation

XON_ITEM = {
    "breach": "LinkedIn",
    "details": "In 2012 <b>LinkedIn</b> was breached &amp; passwords leaked.",
    "domain": "linkedin.com",
    "industry": "Information Technology",
    "password_risk": "easytocrack",
    "verified": "Yes",
    "xposed_data": "Email addresses;Passwords",
    "xposed_date": "2012",
    "xposed_records": 164611595,
}


def test_normalise_xon():
    b = normalise_xon(XON_ITEM)
    assert b["name"] == "LinkedIn"
    assert b["password_exposed"] is True
    assert b["password_risk"] == "easytocrack"
    assert b["description"] == "In 2012 LinkedIn was breached & passwords leaked."
    assert b["data"] == ["Email addresses", "Passwords"]
    assert b["verified"] is True


def test_normalise_xon_without_passwords_has_no_risk():
    b = normalise_xon({**XON_ITEM, "xposed_data": "Email addresses;Names"})
    assert b["password_exposed"] is False
    assert b["password_risk"] == "none"


def test_normalise_hibp():
    b = normalise_hibp(
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "PwnCount": 152445165,
            "Description": "<p>Big one</p>",
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": True,
            "IsSensitive": False,
        }
    )
    assert b["password_exposed"] is True  # "Password hints" alone wouldn't count
    assert b["date"] == "2013-10-04"
    assert b["description"] == "Big one"
    assert b["source"] == "hibp"


# ---------------------------------------------------------------- findings & advice


def _collect(found):
    out = []
    _breach_findings(found, lambda m, s, t, d="": out.append((s, t)))
    return out


def test_breach_findings_severities():
    weak = normalise_xon(XON_ITEM)
    strong = normalise_xon({**XON_ITEM, "breach": "Dropbox", "password_risk": "hardtocrack"})
    nopw = normalise_xon({**XON_ITEM, "breach": "Canva", "xposed_data": "Email addresses"})
    out = _collect([weak, strong, nopw])
    assert ("high", "Password exposed in readable or easy-to-crack form (1)") in out
    assert ("medium", "Password hash exposed in 1 breach(es)") in out
    assert ("info", "Email found in 3 data breach(es)") in out


def test_breach_findings_no_password_is_medium():
    out = _collect([normalise_xon({**XON_ITEM, "xposed_data": "Email addresses"})])
    assert out == [("medium", "Email found in 1 data breach(es)")]


def test_advice_mentions_sites_to_change():
    tips = advice([normalise_xon(XON_ITEM)], "free")
    assert tips[0]["title"] == "Change these passwords now"
    assert "LinkedIn" in tips[0]["detail"]
    assert advice([], "free")[0]["title"].startswith("No known breaches")


def test_provider_type_and_gravatar_hash():
    assert provider_type("gmail.com", set()) == "free"
    assert provider_type("mailinator.com", {"mailinator.com"}) == "disposable"
    assert provider_type("monash.edu", set()) == "custom"
    # Gravatar hashes the trimmed, lower-cased address with SHA-256
    assert gravatar_hash(" Test@Example.com ") == gravatar_hash("test@example.com")
    assert len(gravatar_hash("test@example.com")) == 64


# ---------------------------------------------------------------- reports

EMAIL_RESULT = {
    "meta": {
        "kind": "email",
        "email": "you@example.com",
        "domain": "example.com",
        "started": "2026-01-01T00:00:00+00:00",
        "duration_s": 1.0,
        "version": "t",
        "options": {"hibp": False},
    },
    "breaches": {"provider": "XposedOrNot", "checked": True, "items": [normalise_xon(XON_ITEM)]},
    "domain_info": {
        "provider_type": "custom",
        "mx": ["0 ."],
        "email_security": {"spf": None, "dmarc": None},
    },
    "gravatar": {"hash": "x", "has_avatar": False, "avatar_url": None, "profile": None},
    "findings": [
        {"severity": "high", "module": "breaches", "title": "<script>x</script>", "detail": ""}
    ],
    "errors": {},
    "advice": advice([normalise_xon(XON_ITEM)], "custom"),
    "summary": {
        "findings": {"high": 1, "medium": 0, "low": 0, "info": 0},
        "breaches": 1,
        "password_breaches": 1,
        "plaintext_breaches": 1,
        "first_year": "2012",
        "latest_year": "2012",
    },
}


def test_email_reports_render_and_escape():
    html = to_html(EMAIL_RESULT)
    assert "you@example.com" in html and "LinkedIn" in html
    assert "<script>x</script>" not in html
    md = to_markdown(EMAIL_RESULT)
    assert md.startswith("# domainscope email report: you@example.com")
    assert "| LinkedIn | 2012 | easytocrack |" in md
    assert report_name(EMAIL_RESULT) == "you_at_example.com"


# ---------------------------------------------------------------- settings + API


def test_settings_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    s = Settings(tmp_path)
    assert s.hibp_key is None
    s.set_hibp_key("  abcd1234efgh5678 ")
    assert s.hibp_key == "abcd1234efgh5678"
    assert s.hibp_key_source == "settings"
    monkeypatch.setenv("HIBP_API_KEY", "fromenv")
    assert s.hibp_key == "fromenv" and s.hibp_key_source == "environment"
    assert mask("abcd1234efgh5678") == "abcd…5678"


def test_email_check_api(tmp_path, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    seen = {}

    def fake_email(email, key, progress):
        seen["key"] = key
        progress("Breaches", "1 found", True)
        return json.loads(
            json.dumps({**EMAIL_RESULT, "meta": {**EMAIL_RESULT["meta"], "email": email}})
        )

    client = TestClient(create_app(tmp_path, email_fn=fake_email, allowed_hosts=["testserver"]))
    assert client.post("/api/email-checks", json={"email": "nope"}).status_code == 400

    assert client.put("/api/settings", json={"hibp_api_key": "abcd1234efgh5678"}).json()[
        "hibp_key_set"
    ]
    settings = client.get("/api/settings").json()
    assert settings["hibp_key_masked"] == "abcd…5678"
    assert "abcd1234efgh5678" not in json.dumps(settings)  # never echo the full key

    resp = client.post("/api/email-checks", json={"email": "Me@Example.com"})
    assert resp.status_code == 202 and resp.json()["target"] == "me@example.com"
    scan_id = resp.json()["id"]
    with client.stream("GET", f"/api/scans/{scan_id}/events") as stream:
        lines = [x for x in stream.iter_lines() if x.startswith("data: ")]
    assert json.loads(lines[-1][6:])["type"] == "done"
    assert seen["key"] == "abcd1234efgh5678"

    listing = client.get("/api/scans").json()["scans"][0]
    assert listing["kind"] == "email" and listing["target"] == "me@example.com"
    assert listing["breaches"] == 1
    dl = client.get(f"/api/scans/{scan_id}/report/md?download=true")
    assert "me_at_example.com" in dl.headers["content-disposition"]
